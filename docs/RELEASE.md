# Release and Signing Plan

NoUSB OS Switcher plans and verifies changes to boot paths, so every release binary must be attributable and verifiable before anyone runs it. This plan covers the CLI/TUI (`nousb`). The Tauri desktop app follows the same rules once its command bridge ships.

## Release Gates

A tag is cut only when all of these pass on the tagged commit:

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` on Ubuntu and Windows (the `ci` workflow).
- Default features only. Release builds never enable `real-windows-boot`, `real-linux-boot`, `real-macos-boot`, `destructive-tests`, or `technician-mode`. The release workflow asserts this by building with `--locked` and no feature flags.
- `docs/VM_ONE_SHOT.md` evidence is current for any change that touches the planner, the executor gate, or a boot backend model.

## Build and Provenance (automated today)

`.github/workflows/release.yml` runs on `v*` tags and:

1. Builds `nousb` with `cargo build --release --locked -p nousb` on `ubuntu-latest` and `windows-latest`.
2. Packages each binary with `README.md`, `LICENSE-APACHE`, `LICENSE-MIT`, `CHANGELOG.md`, and `docs/SAFETY_MODEL.md`. The workspace is licensed `Apache-2.0 OR MIT`.
3. Writes `SHA256SUMS` over all archives.
4. Creates GitHub build-provenance attestations (SLSA v1 via `actions/attest-build-provenance`) for every archive. Verify with `gh attestation verify <archive> --repo jebarson-caleb/RevX`.
5. Publishes a draft GitHub release, which a maintainer reviews before publishing.

## Signing (requires maintainer credentials; not yet automated)

| Artifact | Mechanism | Key custody |
| --- | --- | --- |
| Windows `nousb.exe` and future MSI | Authenticode via Azure Trusted Signing (or an EV certificate in an HSM) with RFC 3161 timestamping | Cloud HSM; never a file in the repository or CI secrets |
| Linux tarballs | `SHA256SUMS` signed with minisign (`SHA256SUMS.minisig`); public key committed to `packaging/` and published on the release page | Offline maintainer key |
| Future deb/rpm repositories | Repository metadata signed with a dedicated OpenPGP subkey | Offline primary, subkey on a hardware token |
| Desktop app updater | Tauri updater signature | Separate key, never reused for binaries |

Until signing is automated, releases stay drafts or are marked pre-release, and the release notes say that only provenance attestations and checksums are available.

## Supply Chain

- `Cargo.lock` is committed and release builds use `--locked`.
- Before 1.0: add `cargo deny check` (licenses: Apache-2.0, MIT, BSD, ISC, Unicode, Zlib; advisories; banned duplicate TLS stacks) and a CycloneDX SBOM (`cargo cyclonedx`) attached to each release.
- Pinned installer artifacts (`crates/nousb-installer-profiles/profiles/*.toml`) and the QEMU runtime manifest are data, not code. Changing a pinned hash or URL requires a release note.
- The disposable-VM runtime is assembled by `nousb vm qemu bootstrap-runtime` from signed Alpine packages and is never shipped inside a release.

## Verification for Users

```sh
sha256sum -c SHA256SUMS
minisign -Vm SHA256SUMS -p nousb-release.pub     # once signing is automated
gh attestation verify nousb-<version>-x86_64-linux.tar.gz --repo jebarson-caleb/RevX
```

On Windows, also check the Authenticode signature (`Get-AuthenticodeSignature .\nousb.exe`) once signing is automated.
