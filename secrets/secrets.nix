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
