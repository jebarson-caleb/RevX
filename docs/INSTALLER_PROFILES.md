# Installer Profiles

Installer profiles are versioned TOML files in `crates/nousb-installer-profiles/profiles`.

```toml
schema_version = "1"
id = "ubuntu-24.04-desktop"
name = "Ubuntu Desktop"
vendor = "Canonical"
version = "24.04.4 LTS"
architecture = "x86_64"
source_url = "https://releases.ubuntu.com/24.04/ubuntu-24.04.4-desktop-amd64.iso"
checksum_url = "https://releases.ubuntu.com/24.04/SHA256SUMS"
sha256 = "<official sha256>"
artifact_filename = "ubuntu-24.04.4-desktop-amd64.iso"
artifact_size_bytes = "6655619072"
homepage = "https://ubuntu.com"
required_free_space_gb = 8
supported_staging_strategies = ["iso_loopback", "kernel_initrd"]
secure_boot_notes = "Use official signed boot assets."
known_limitations = ["Default build only creates dry-run plans."]
```

Downloadable profiles must pin an official HTTPS artifact URL, safe filename, exact nonzero byte size, and 64-character SHA-256. The downloader rejects HTTPS downgrade redirects, validates response length where available, hashes the completed file in-process on Windows and Linux, and atomically promotes a verified `.part` file. Profiles such as the Windows 11 consumer ISO that lack a stable vendor URL remain catalog entries but fail closed for manifest/download commands.

Validate the embedded catalog with:

```sh
cargo run -p nousb -- catalog validate
cargo run -p nousb -- --json image manifest ubuntu-24.04-desktop
cargo run -p nousb -- --json image manifest fedora-44-workstation
```

## Signature Chain

A pinned SHA-256 only says which bytes NoUSB expects. `signing_key` ties that digest to the vendor:

```toml
signature_url = "https://releases.ubuntu.com/24.04/SHA256SUMS.gpg"
signing_key = "ubuntu-cdimage-2012"
```

```sh
cargo run -p nousb -- image verify-signature ubuntu-24.04-server
cargo run -p nousb -- --json image verify-signature fedora-44-workstation
```

`image verify-signature` downloads the checksum document over HTTPS. When `signature_url` differs from `checksum_url` it also downloads the detached signature (Ubuntu); otherwise it treats the checksum document as clearsigned (Fedora). It then verifies the OpenPGP signature in-process with rPGP against the primary key or a subkey of the pinned vendor key. Finally, it requires the profile's pinned SHA-256 to appear in the *signed* text for the exact artifact filename, in either GNU (`<hex> *<file>`) or BSD (`SHA256 (<file>) = <hex>`) layout. It never trusts an unsigned line.

Vendor keys live in `crates/nousb-installer-profiles/keys/` and are pinned by fingerprint in `crates/nousb-core/src/provenance.rs`. Loading a key also checks its fingerprint and its self-signatures.

| `signing_key` | Owner | Fingerprint | Cross-checked against |
| --- | --- | --- | --- |
| `ubuntu-cdimage-2012` | Ubuntu CD Image Automatic Signing Key (2012) | `8439 38DF 228D 22F7 B374 2BC0 D94A A3F0 EFE2 1092` | Ubuntu's download-verification tutorial and keyserver.ubuntu.com |
| `fedora-44` | Fedora (44) | `36F6 12DC F27F 7D1A 48A8 35E4 DBFC F71C 6D9F 90A6` | https://fedoraproject.org/security/ and https://fedoraproject.org/fedora.gpg |

The Windows 11 profile has no `signing_key` and fails closed. Signed fixtures captured on 2026-10-22 under `crates/nousb-core/tests/fixtures/` let the tests prove offline that real vendor signatures verify and that tampered text or the wrong key is rejected. `.gitattributes` keeps those fixtures and keys byte-exact.

Adding or rotating a key is a release-noted change: export it minimally (`gpg --armor --export-options export-minimal --export <fingerprint>`), cross-check the fingerprint against at least one vendor-controlled page, then pin it.
