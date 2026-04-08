# NixOS User Auth Hardening via agenix

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Beads:** harmony-os-2m4 (user auth), harmony-os-zy2 (WiFi PSK — resolved as won't-fix)

**Goal:** Replace the plaintext `initialPassword` with an agenix-managed `hashedPasswordFile` for the `zeblith` user on all RPi5 hosts, and re-enable `wheelNeedsPassword` for sudo.

**Prerequisite:** None. SSH is already key-only (PR #93).

---

## Architecture

agenix is added as a flake input. One encrypted secret file (`secrets/user-password.age`) contains the hashed password for the `zeblith` user. Each RPi5 host decrypts it at NixOS activation time to `/run/agenix/user-password`, referenced via `hashedPasswordFile`.

**Data flow:**

```
mkpasswd → hash string → age encrypt (Mac key + host keys) → secrets/user-password.age
  → nix build → agenix module decrypts at activation → /run/agenix/user-password
  → users.users.zeblith.hashedPasswordFile points to it
```

### What changes

- **`flake.nix`** — Add `agenix` flake input, add `agenix.nixosModules.default` to `mkRpi5` modules list.

- **`secrets/secrets.nix`** — agenix rules file declaring which age/SSH public keys can decrypt which secrets. Lists the operator's age public key and all four RPi5 SSH host public keys. Maps `user-password.age` to the full key set.

- **`secrets/user-password.age`** — Age-encrypted file containing the output of `mkpasswd -m sha-512`. Encrypted to the operator's age key (for editing) and all RPi5 host keys (for runtime decryption).

- **`nixos/rpi5-base.nix`** — Five changes:
  1. Declare `age.secrets.user-password` (source file, owner, permissions).
  2. Set `users.users.zeblith.hashedPasswordFile = config.age.secrets.user-password.path`.
  3. Set `security.sudo.wheelNeedsPassword = true`.
  4. Replace `TODO(harmony-os-wifi-secrets)` comment with rationale for keeping PSK plaintext.
  5. Replace `TODO(harmony-os-user-secrets)` comment with note that migration is done.

### What stays the same

- `initialPassword = "harmony"` — kept as HDMI console emergency fallback. NixOS uses `hashedPasswordFile` when the file exists; `initialPassword` activates only if the agenix secret is missing (first flash, decryption failure).
- WiFi PSK `"ZEBLITHIC"` — stays plaintext. The value is the org name, not sensitive. NetworkManager has no native secret-file support; adding a custom systemd service to inject it provides zero security value.
- SSH config — already key-only (`PasswordAuthentication = false`).
- Host-specific configs (luna.nix, sol.nix, terra.nix, archivist.nix) — unchanged.
- harmony-node-service.nix — unchanged.
- Boot config — unchanged.

---

## Key Management

### Operator key (Mac build machine)

Generate one age keypair. Private key stored at `~/.config/sops/age/keys.txt` (standard location, never committed). Public key referenced in `secrets/secrets.nix`.

```bash
age-keygen -o ~/.config/sops/age/keys.txt
# Prints public key: age1...
```

### RPi5 host keys (runtime decryption)

Each RPi5's SSH ed25519 host key doubles as an agenix decryption key. Collect public keys:

```bash
ssh-keyscan -t ed25519 harmony-luna.local
ssh-keyscan -t ed25519 harmony-terra.local
ssh-keyscan -t ed25519 harmony-sol.local
ssh-keyscan -t ed25519 harmony-archive.local
```

Convert to age format and add to `secrets/secrets.nix`.

### secrets/secrets.nix structure

```nix
let
  # Operator age key (Mac build machine)
  operator = "age1...";

  # RPi5 SSH host keys (converted to age format via ssh-to-age)
  luna    = "ssh-ed25519 AAAA...";
  terra   = "ssh-ed25519 AAAA...";
  sol     = "ssh-ed25519 AAAA...";
  archive = "ssh-ed25519 AAAA...";

  allHosts = [ luna terra sol archive ];
  allKeys  = [ operator ] ++ allHosts;
in
{
  "user-password.age".publicKeys = allKeys;
}
```

---

## Bootstrap: First Flash of a New Host

1. Flash SD image — host key doesn't exist yet, agenix secret file missing at `/run/agenix/user-password`.
2. `initialPassword = "harmony"` provides HDMI console login.
3. Host boots, generates SSH host key automatically.
4. Operator SSHes in with their ed25519 key.
5. Collect new host's public key, add to `secrets/secrets.nix`, re-encrypt all secrets:
   ```bash
   agenix -r -i ~/.config/sops/age/keys.txt
   ```
6. Rebuild and deploy. On next activation, agenix decrypts successfully, `hashedPasswordFile` takes over.

---

## WiFi PSK Resolution (harmony-os-zy2)

The WiFi PSK `"ZEBLITHIC"` stays plaintext. Rationale:

- The value is the organization name, not a real secret.
- NetworkManager `ensureProfiles` has no native secret-file support. Injecting a PSK from a file requires a custom systemd oneshot service to template NM profiles and restart NetworkManager — meaningful complexity for zero security gain.
- The agenix infrastructure pattern is established by the user auth bead. If a real WiFi secret is needed in the future, the plumbing exists.

The `TODO(harmony-os-wifi-secrets)` comment is replaced with this rationale. Bead harmony-os-zy2 is closed as won't-fix.

---

## Testing

NixOS config — no unit tests. Validation:

1. **`nix flake check`** — syntax and type errors in NixOS modules.
2. **`nix build .#sdImage-luna --system aarch64-linux --dry-run`** — full module evaluation succeeds (verifies agenix module wiring, hashedPasswordFile reference, secret declaration).
3. **Manual on hardware** — after flash: agenix decrypts, password login works on console, `sudo` prompts for password.

### Manual step

The `agenix -e secrets/user-password.age` encryption step requires the operator's age private key. This is a manual step performed by the operator, not automatable by a subagent. The implementation plan marks it explicitly.

---

## Scope Boundary

**In scope:**
- agenix flake input + module wiring in `flake.nix`
- `secrets/secrets.nix` key declarations
- `secrets/user-password.age` encrypted hashed password (manual encryption step)
- `hashedPasswordFile` on zeblith user in `rpi5-base.nix`
- `wheelNeedsPassword = true` in `rpi5-base.nix`
- Remove TODO comments, add rationale comments
- Close harmony-os-zy2 as won't-fix

**Out of scope:**
- Removing `initialPassword` (kept as emergency fallback)
- WiFi PSK encryption (not a real secret, NM lacks native support)
- SSH config changes (already hardened)
- Host-specific config changes
- Per-host secret differentiation (all hosts share the same user password)
- Automated secret rotation
