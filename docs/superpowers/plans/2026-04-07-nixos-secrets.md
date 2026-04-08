# NixOS User Auth Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the plaintext `initialPassword` with an agenix-managed `hashedPasswordFile` for the `zeblith` user, re-enable `wheelNeedsPassword`, and close the WiFi PSK bead as won't-fix.

**Architecture:** agenix is added as a flake input. One age-encrypted secret file contains the hashed password. The agenix NixOS module decrypts it at activation time to `/run/agenix/user-password`, referenced via `hashedPasswordFile`. The `initialPassword` is kept as HDMI console emergency fallback.

**Tech Stack:** NixOS, agenix, age encryption, mkpasswd

---

## Context

### Current state

- `flake.nix` has 4 inputs: nixpkgs, fenix, flake-utils, nixos-hardware
- `mkRpi5` helper builds NixOS configs for 4 RPi5 hosts (luna, terra, sol, archive)
- `nixos/rpi5-base.nix` is the shared base config imported by all hosts
- `users.users.zeblith.initialPassword = "harmony"` (plaintext, line 230)
- `security.sudo.wheelNeedsPassword = false` (line 239)
- WiFi PSK `"ZEBLITHIC"` in three NM profiles (lines 157, 174, 193)
- SSH is already key-only (`PasswordAuthentication = false`, line 218)
- No `secrets/` directory exists yet

### Key insight: manual operator step required

agenix encrypts secrets with the operator's age private key. This key lives on the operator's Mac (`~/.config/sops/age/keys.txt`), not in the repo. The actual encryption step (`agenix -e secrets/user-password.age`) cannot be performed by a subagent. Tasks 1-2 wire everything up with a placeholder `.age` file; the "Manual Operator Steps" section at the end documents how to create the real encrypted secret.

---

### Task 1: Add agenix flake input and wire into mkRpi5

**Files:**
- Modify: `flake.nix:9-14` (inputs block)
- Modify: `flake.nix:19` (outputs function args)
- Modify: `flake.nix:102-110` (mkRpi5 modules list)

- [ ] **Step 1: Add agenix to flake inputs**

In `flake.nix`, add `agenix` to the `inputs` block (after the `nixos-hardware` line, before the closing `};`):

```nix
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixos-hardware.url = "github:NixOS/nixos-hardware";
    agenix = {
      url = "github:ryantm/agenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
```

`inputs.nixpkgs.follows` tells agenix to use our nixpkgs instead of bringing its own — avoids duplicate nixpkgs evaluations.

- [ ] **Step 2: Add agenix to outputs function arguments**

Change the outputs line from:

```nix
  outputs = { self, nixpkgs, fenix, flake-utils, nixos-hardware }:
```

To:

```nix
  outputs = { self, nixpkgs, fenix, flake-utils, nixos-hardware, agenix }:
```

- [ ] **Step 3: Add agenix module to mkRpi5**

In the `mkRpi5` helper function, add `agenix.nixosModules.default` to the modules list. Change from:

```nix
      mkRpi5 = hostConfig: nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = { inherit harmonyNodePkg; };
        modules = [
          "${nixpkgs}/nixos/modules/installer/sd-card/sd-image-aarch64.nix"
          nixos-hardware.nixosModules.raspberry-pi-5
          hostConfig
        ];
      };
```

To:

```nix
      mkRpi5 = hostConfig: nixpkgs.lib.nixosSystem {
        system = "aarch64-linux";
        specialArgs = { inherit harmonyNodePkg; };
        modules = [
          "${nixpkgs}/nixos/modules/installer/sd-card/sd-image-aarch64.nix"
          nixos-hardware.nixosModules.raspberry-pi-5
          agenix.nixosModules.default
          hostConfig
        ];
      };
```

- [ ] **Step 4: Lock the new input**

Run:

```bash
nix flake lock --update-input agenix
```

Expected: `flake.lock` is updated with the agenix input. Output shows something like:
```
• Updated input 'agenix': ...
```

- [ ] **Step 5: Validate flake**

Run:

```bash
nix flake check 2>&1 | head -20
```

Expected: No errors. The agenix module is now available but not yet used by any config (no `age.secrets` declarations yet), so evaluation should pass cleanly.

If `nix flake check` fails with cross-system evaluation errors (macOS can't evaluate aarch64-linux NixOS configs), use this alternative:

```bash
nix eval .#nixosConfigurations.rpi5-luna.config.system.build.toplevel.drvPath 2>&1 | head -5
```

Expected: A Nix store path string (e.g., `/nix/store/...-nixos-system-harmony-luna-....drv`), confirming the NixOS config evaluates successfully with the agenix module loaded.

- [ ] **Step 6: Commit**

```bash
git add flake.nix flake.lock
git commit -m "feat(nixos): add agenix flake input for secrets management

Wire agenix module into mkRpi5 so all RPi5 hosts can decrypt
age-encrypted secrets at NixOS activation time.

Bead: harmony-os-2m4"
```

---

### Task 2: Create secrets infrastructure and harden rpi5-base.nix

**Files:**
- Create: `secrets/secrets.nix`
- Create: `secrets/user-password.age`
- Modify: `nixos/rpi5-base.nix:136-199` (WiFi TODO comment)
- Modify: `nixos/rpi5-base.nix:222-239` (users + sudo section)

- [ ] **Step 1: Create secrets/secrets.nix**

Create `secrets/secrets.nix` with placeholder keys. This file is consumed by the `agenix` CLI (not by NixOS evaluation) to determine which keys can encrypt/decrypt each secret.

```nix
# agenix secret rules — maps secrets to the public keys that can decrypt them.
#
# Key sources:
#   - operator: age public key from ~/.config/sops/age/keys.txt on build machine
#   - hosts: SSH ed25519 host keys from each RPi5 (ssh-keyscan -t ed25519 <host>.local)
#
# After updating keys, re-encrypt all secrets:
#   cd secrets && agenix -r -i ~/.config/sops/age/keys.txt
#
# PLACEHOLDER: Replace these keys with real values before running agenix -e.
# See "Manual Operator Steps" in docs/superpowers/plans/2026-04-07-nixos-secrets.md.

let
  # Operator age key (Mac build machine — run `age-keygen` to generate)
  operator = "age1PLACEHOLDER_REPLACE_WITH_REAL_AGE_PUBLIC_KEY";

  # RPi5 SSH host keys (run: ssh-keyscan -t ed25519 harmony-<name>.local)
  luna    = "ssh-ed25519 PLACEHOLDER_LUNA_HOST_KEY";
  terra   = "ssh-ed25519 PLACEHOLDER_TERRA_HOST_KEY";
  sol     = "ssh-ed25519 PLACEHOLDER_SOL_HOST_KEY";
  archive = "ssh-ed25519 PLACEHOLDER_ARCHIVE_HOST_KEY";

  allHosts = [ luna terra sol archive ];
  allKeys  = [ operator ] ++ allHosts;
in
{
  "user-password.age".publicKeys = allKeys;
}
```

- [ ] **Step 2: Create placeholder user-password.age**

Create an empty placeholder file. The operator replaces this with a real age-encrypted file using `agenix -e`.

```bash
mkdir -p secrets
touch secrets/user-password.age
```

The file must exist for NixOS evaluation to succeed (the `age.secrets.user-password.file` path is resolved at eval time), but its content is only read at runtime by the agenix activation script.

- [ ] **Step 3: Add agenix secret declaration to rpi5-base.nix**

In `nixos/rpi5-base.nix`, add the agenix secret declaration in the Users section. Replace the entire Users + sudo block (lines 222-239) with:

```nix
  # --- Users ---

  # agenix-managed hashed password for console login.
  # Decrypted at NixOS activation time to /run/agenix/user-password.
  # Source: secrets/user-password.age (age-encrypted mkpasswd -m sha-512 output).
  age.secrets.user-password.file = ../secrets/user-password.age;

  users.users.zeblith = {
    isNormalUser = true;
    extraGroups = [ "wheel" "networkmanager" "dialout" ];
    # hashedPasswordFile takes precedence when the agenix secret is available.
    # initialPassword is the HDMI-console emergency fallback: it activates only
    # if the agenix secret file is missing (first flash, decryption failure).
    # SSH remains key-only (PasswordAuthentication = false above).
    hashedPasswordFile = config.age.secrets.user-password.path;
    initialPassword = "harmony";
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM+Y/OkDTbAa/T0TXHESg7ZRkXOj0rJQ3qUlCR9STo7t zeblith@gmail.com"  # AVALON
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC9fSUat8x5KnIbuqbThWn7fqm3ork11fsvaqxAY/b5F zeblith@gmail.com"  # MacBook Pro
    ];
  };

  # Sudo requires password now that hashedPasswordFile is in place.
  security.sudo.wheelNeedsPassword = true;
```

- [ ] **Step 4: Update WiFi PSK comment**

In `nixos/rpi5-base.nix`, replace the WiFi TODO comment block (lines 136-142). Change from:

```nix
  # Pre-configured WiFi networks (RPi5 has built-in Broadcom WiFi).
  # Prioritized: MLO (WiFi 7) > 5GHz > 2.4GHz. Ethernet always preferred if available.
  #
  # TODO(harmony-os-wifi-secrets): The PSK is committed in plaintext. This is
  # intentionally accepted for now (it's the org name, not a secret), but should
  # be migrated to agenix or sops-nix for proper secrets management.
  networking.networkmanager.ensureProfiles.profiles = {
```

To:

```nix
  # Pre-configured WiFi networks (RPi5 has built-in Broadcom WiFi).
  # Prioritized: MLO (WiFi 7) > 5GHz > 2.4GHz. Ethernet always preferred if available.
  #
  # The PSK is the org name (ZEBLITHIC), not a real secret. Kept in plaintext
  # because NetworkManager ensureProfiles has no native secret-file support —
  # injecting from agenix would require a custom systemd oneshot to template
  # NM profiles, adding meaningful complexity for zero security gain.
  networking.networkmanager.ensureProfiles.profiles = {
```

- [ ] **Step 5: Validate NixOS evaluation**

Run:

```bash
nix flake check 2>&1 | head -20
```

If cross-system evaluation fails on macOS, use:

```bash
nix eval .#nixosConfigurations.rpi5-luna.config.users.users.zeblith.hashedPasswordFile 2>&1
```

Expected: `/run/agenix/user-password` (the path where agenix decrypts the secret at runtime).

Also verify the archivist config (imports rpi5-base.nix, so inherits the agenix secret):

```bash
nix eval .#nixosConfigurations.rpi5-archive.config.users.users.zeblith.hashedPasswordFile 2>&1
```

Expected: Same path — `/run/agenix/user-password`.

- [ ] **Step 6: Commit**

```bash
git add secrets/secrets.nix secrets/user-password.age nixos/rpi5-base.nix
git commit -m "feat(nixos): add hashedPasswordFile via agenix, re-enable wheelNeedsPassword

- Declare age.secrets.user-password in rpi5-base.nix
- Set hashedPasswordFile = config.age.secrets.user-password.path
- Keep initialPassword as HDMI console emergency fallback
- Re-enable security.sudo.wheelNeedsPassword (was disabled pending secrets)
- Resolve WiFi PSK TODO: not a real secret, keep plaintext with rationale

Beads: harmony-os-2m4, harmony-os-zy2"
```

- [ ] **Step 7: Close harmony-os-zy2 as won't-fix**

```bash
bd close harmony-os-zy2 --reason="Won't fix — WiFi PSK is the org name (ZEBLITHIC), not sensitive. NetworkManager ensureProfiles lacks native secret-file support. agenix pattern established by harmony-os-2m4 for actual secrets."
```

---

## Manual Operator Steps

These steps require the operator's private age key and access to the RPi5 hosts. They cannot be performed by a subagent.

### 1. Generate age keypair (one-time)

```bash
# Install age if not present
brew install age

# Generate keypair
age-keygen -o ~/.config/sops/age/keys.txt
```

This prints the public key (e.g., `age1abc123...`). Copy it.

### 2. Collect RPi5 SSH host keys

```bash
ssh-keyscan -t ed25519 harmony-luna.local 2>/dev/null | awk '{print $2, $3}'
ssh-keyscan -t ed25519 harmony-terra.local 2>/dev/null | awk '{print $2, $3}'
ssh-keyscan -t ed25519 harmony-sol.local 2>/dev/null | awk '{print $2, $3}'
ssh-keyscan -t ed25519 harmony-archive.local 2>/dev/null | awk '{print $2, $3}'
```

Each prints `ssh-ed25519 AAAA...`. Copy these.

### 3. Update secrets/secrets.nix with real keys

Replace the placeholder values in `secrets/secrets.nix` with the real public keys from steps 1-2.

### 4. Install agenix CLI

```bash
nix profile install github:ryantm/agenix
```

Or use `nix run github:ryantm/agenix --` as a prefix for agenix commands.

### 5. Create the encrypted password file

```bash
# Generate a SHA-512 hashed password (will prompt for password interactively)
mkpasswd -m sha-512

# Encrypt it with agenix (opens $EDITOR — paste the hash, save, quit)
cd /path/to/harmony-os
agenix -e secrets/user-password.age -i ~/.config/sops/age/keys.txt
```

The `agenix -e` command reads `secrets/secrets.nix` to determine which public keys to encrypt to, opens `$EDITOR` for you to paste the hash, then writes the encrypted file.

### 6. Commit the real secret and updated keys

```bash
git add secrets/secrets.nix secrets/user-password.age
git commit -m "chore(nixos): add real agenix-encrypted user password"
```

### 7. Verify on hardware

Flash an SD image (`nix build .#sdImage-luna --system aarch64-linux`), boot the RPi5, and verify:
- Console login with the new password works
- `sudo` prompts for password
- SSH key-only auth still works
- `ls -la /run/agenix/user-password` shows the decrypted file (owned by root, mode 0400)
