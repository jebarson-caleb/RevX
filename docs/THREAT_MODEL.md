# Threat Model

NoUSB assumes boot configuration is high-value system state. The product must not become a persistence mechanism, policy bypass, or unsafe downloader.

## In Scope

- Prevent accidental boot misconfiguration.
- Prevent unverified installer execution.
- Redact secrets from logs.
- Avoid hidden telemetry.
- Preserve user agency with explicit confirmations.
- Keep default boot target unchanged where possible.

## Trust Boundaries

| Input | Trusted because | Checked by |
| --- | --- | --- |
| Installer ISO bytes | Exact size and SHA-256 pinned in the profile | Downloader and `image verify-profile` |
| The pinned digest itself | Listed in the vendor's OpenPGP-signed checksum document | `image verify-signature`, using fingerprint-pinned keys |
| Vendor signing keys | Fingerprints cross-checked against vendor-controlled pages before pinning | Fingerprint and self-signature check on every load |
| Disposable-VM runtime | Signed Alpine packages, verified by `apk` with the WSL distribution's keys | `bootstrap-runtime` manifest (package versions and key digests) |
| Guest-side ISO transport in rehearsals | Isolated QEMU user network to a host-local HTTP source; plain HTTP | Size/digest pinning only; guest HTTPS remains an open gate |
| Saved operation reports | Written by NoUSB under `.nousb/` | Strict schema parse before resume or rollback |
| Host inventory | Read-only, non-elevated queries | Unknowns stay explicit; nothing is inferred from missing data |

## Out Of Scope

- Bypassing Secure Boot, SIP, TPM, BitLocker, FileVault, activation, licensing, or vendor policy.
- Storing raw recovery keys unless a future encrypted vault is explicitly implemented.
- Firmware modification.
- Stealth persistence.

