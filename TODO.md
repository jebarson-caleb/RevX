# NoUSB OS Switcher To-Do

Use `START_HERE.md` first, then this file as the detailed project queue when starting a new Codex chat.

## Current Usable Version

The repository now contains a safe, non-destructive scaffold for NoUSB OS Switcher.

Working pieces:

- Rust workspace with core, CLI, platform skeleton, and profile crates.
- Cross-platform guided terminal application launched with `nousb tui`, covering inspect, profile selection, delivery assessment, manifest/probe, typed download/staging, and plan preview.
- CLI commands for doctor, inspect, catalog, plan preview, artifact manifest/probe/download, checksum verification, staging preview/bundle creation, recovery-pack creation, and log export.
- CLI global options for `--json`, `--dry-run`, and guarded `--yes`.
- Risk model and typed confirmation requirements.
- Typed `BootPlan` in every operation plan, preferring one-time boot/fallback behavior and disallowing permanent boot-order changes by default.
- Explicit safe executor gate that refuses default-build execution and blocks `--yes` for high/critical plans.
- Built-in installer profiles for Ubuntu 24.04.4, Fedora 44, and Windows 11.
- Direct official HTTPS artifact manifests with pinned size and SHA-256 for Ubuntu and Fedora; Windows fails closed because its consumer URL is session-generated.
- Resumable, locked downloads with HTTPS downgrade rejection, exact-size checks, in-process SHA-256, and atomic finalization.
- ISO9660 staging inspection and extraction limited to profile-declared paths, with per-output hashes and `execution_enabled=false`.
- Deterministic synthetic ISO9660 end-to-end test covering verification through final bundle output.
- Typed one-shot boot rehearsal for UEFI BootNext, Windows BCD bootsequence, systemd-boot one-shot, and GRUB next-entry.
- Complete-cycle plus eight interruption scenarios that preserve the original default/order and clean temporary selector/assets.
- Project-local `.nousb/vm-rehearsals` state-machine reports plus real disposable QEMU reports under `.nousb/vm/qemu`.
- Project-local QEMU 10.1.5/OVMF runtime assembled from Alpine v3.23 signed packages and launched through the existing WSL2 environment without installing into Windows.
- Real OVMF/QMP smoke evidence with only read-only firmware code and a disposable variables copy attached.
- Real Ubuntu 24.04.4 netboot kernel/initrd execution through initramfs with QMP-confirmed empty block-device list; explicitly labeled direct-kernel, transport-only, and not full-payload `toram` evidence.
- Pinned Ubuntu 24.04.4 Server profile and verified 3,405,469,696-byte ISO, including official `BOOTX64.EFI`, GRUB, MOK manager, kernel, and initrd hashes.
- Typed direct-kernel full-ISO rehearsal proving the complete installer payload continues from RAM after its owned HTTP source stops, with no block devices attached.
- Typed combined OVMF/official-UEFI/full-ISO rehearsal proving the read-only FAT boot source is deleted before the ISO transfer finishes, the HTTP source is stopped after download, Subiquity and the installer tty continue, and final QMP storage contains only firmware files.
- Combined report truthfully records `secure_boot_enabled=false`, `guest_transport_https=false`, and `fallback_boot_observed=false` as the next safety gates.
- Reproducible runtime: `vm qemu plan-runtime` / `bootstrap-runtime` assemble QEMU 10.1.5, OVMF, busybox, efibootmgr, GRUB, and ESP tools from signed Alpine v3.23 packages and write a manifest with package versions and signing-key digests.
- Disposable current-OS baseline (`rehearse-current-os-baseline`), fixed to boot the live-server initrd with `boot=local`.
- Real UEFI one-shot matrix (`rehearse-current-os-one-shot`): a disposable current OS uses `efibootmgr` to create a temporary entry outside `BootOrder` and arm `BootNext`. Firmware boots the pinned official shim/GRUB/kernel chain exactly once and falls back to the unchanged default after the forced installer failure. The guest cleans up and verifies, with power cut after every transaction step.
- Dev builds hash the 3.2 GiB ISO in about 9 seconds (optimized `sha2` in the dev profile).
- CI runs clippy `-D warnings` and tests on both Ubuntu and Windows.
- Versioned TOML installer profiles under `crates/nousb-installer-profiles/profiles`.
- Profile parser and validation for schema version, supported platforms, staging strategies, and free-space requirements.
- Safe host inspection adapter.
- Read-only Windows/Linux platform inspection for memory and staging space, plus UEFI/Secure Boot and encryption hints where the host exposes them.
- Fake platform adapters for Windows UEFI + BitLocker and Linux GRUB/LUKS/Btrfs low space on the current user-facing surface; macOS remains an exclusion-test scaffold.
- Inventory-aware plan enrichment for encryption, Secure Boot, and low disk space preflight warnings.
- Simulated operation executor with complete, interrupted, failed, and rolled-back reports.
- Persisted execution reports under `.nousb/reports` with `reports list` and `reports show`.
- Diagnostic bundle export under `.nousb/diagnostics` with secret-like log redaction.
- SQLite-backed operation journal with plain-log fallback.
- Recovery pack generator.
- Tauri/React desktop source scaffold.
- Standalone dashboard preview at `apps/desktop/preview.html` covering catalog, planner, fake scenarios, reports, diagnostics, and copyable CLI commands.
- Dashboard data export via `nousb dashboard export` plus portable preview fixture at `apps/desktop/preview-data.json`.
- Typed no-USB delivery assessment for host-staged RAM boot, GRUB loopback, Windows Setup/WinPE, UEFI HTTP Boot, and Dell BIOSConnect comparison.
- Explicit macOS exclusion and truthful `universal_no_usb_guarantee=false` output.
- Docs and original prompt stored in `docs/MASTER_PROMPT.md`.
- GitHub Actions CI workflow for Rust format, clippy, and tests on Ubuntu and Windows.

Verified commands:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p nousb -- doctor
cargo run -p nousb -- tui
cargo run -p nousb -- catalog validate
cargo run -p nousb -- --json image manifest ubuntu-24.04-desktop
cargo run -p nousb -- --json image manifest fedora-44-workstation
cargo run -p nousb -- vm doctor
cargo run -p nousb -- vm rehearse windows-bcd-bootsequence ubuntu-24.04-desktop
cargo run -p nousb -- vm qemu plan-smoke
cargo run -p nousb -- vm qemu smoke "RUN DISPOSABLE QEMU UEFI SMOKE"
cargo run -p nousb -- vm qemu plan-ubuntu-netboot
cargo run -p nousb -- vm qemu rehearse-ubuntu-netboot "RUN DISPOSABLE UBUNTU NETBOOT RAM REHEARSAL"
cargo run -p nousb -- vm qemu plan-ubuntu-full-ram
cargo run -p nousb -- vm qemu rehearse-ubuntu-full-ram "RUN DISPOSABLE UBUNTU FULL ISO RAM REHEARSAL"
cargo run -p nousb -- vm qemu plan-ubuntu-uefi-full-ram
cargo run -p nousb -- vm qemu rehearse-ubuntu-uefi-full-ram "RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL"
cargo run -p nousb -- vm qemu plan-runtime
cargo run -p nousb -- vm qemu bootstrap-runtime "ASSEMBLE PROJECT-LOCAL QEMU RUNTIME"
cargo run -p nousb -- vm qemu plan-current-os-one-shot
cargo run -p nousb -- vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX"
cargo run -p nousb -- workflow assess-fake windows-bitlocker ubuntu-24.04-desktop
cargo run -p nousb -- system inspect-fake windows-bitlocker
cargo run -p nousb -- plan-fake linux-luks-low-space boot-once ubuntu-24.04-desktop
cargo run -p nousb -- --interrupt-after 2 simulate boot-once ubuntu-24.04-desktop
cargo run -p nousb -- reports list
cargo run -p nousb -- diagnostics export
cargo run -p nousb -- dashboard export
cargo run -p nousb -- plan boot-once ubuntu-24.04-desktop
cargo run -p nousb -- --json plan boot-once ubuntu-24.04-desktop
cargo run -p nousb -- --dry-run plan replace-os ubuntu-24.04-desktop
```

## Safety Baseline

Default builds must stay non-destructive.

Do not add real boot, partition, encryption, BCD, GRUB, systemd-boot, EFI, NVRAM, `bless`, or `startosinstall` changes unless they are:

- Isolated behind the relevant feature flag.
- Planned before executed.
- Covered by confirmation gates.
- Logged to the operation journal.
- Tested with fake adapters first.

Current feature flags to preserve:

- `real-windows-boot`
- `real-linux-boot`
- `real-macos-boot`
- `destructive-tests`
- `technician-mode`

## Next Best Steps

Done in this round: the host one-shot boot executor (`nousb boot plan | arm | status | cleanup`) behind `real-windows-boot` / `real-linux-boot`, with fake-backend transaction tests, scripted `bcdedit`/`efibootmgr` tests, the desktop "Boot once" view, and open-source release files. See `docs/PHYSICAL_TESTING.md`.

- Run the physical test matrix in `docs/PHYSICAL_TESTING.md`: Windows NTFS to Ubuntu (casper reading NTFS), Linux ext4 to Ubuntu and Fedora, Secure Boot on and off. Record each run with the "Physical test report" issue template.
- Add a WinPE-based route before claiming Windows as a target; keep Windows 11 fail-closed until then.
- Add `@types/react` and a `tsconfig.json` so the desktop UI is type-checked in CI (Vite only transpiles today).

Done in this round: the disposable current-OS guest, the real UEFI `BootNext` selector, firmware fallback, and the power-loss matrix (former steps 1 and 2); see `docs/VM_ONE_SHOT.md`.

1. Join the one-shot matrix to the full-installer-in-RAM path in a single run. The installer entry boots casper with `url=` and the full verified ISO, then the run proves fallback after a later reboot.
2. Enable OVMF Secure Boot (an Alpine/edk2 `secboot` build with enrolled Microsoft/Canonical keys) for the same matrix, and add a TLS-capable guest recovery endpoint. Keep the current isolated HTTP proof labeled honestly.
3. Build equivalent disposable matrices for Windows BCD `bootsequence`, systemd-boot `LoaderEntryOneShot`, and GRUB `next_entry` (the state-machine rehearsals already exist).
4. Extend read-only inspection with ESP, boot-manager, and network-boot hints; keep unknown values explicit.
5. Add signature-chain verification and provenance metadata on top of the pinned SHA-256 manifests.
6. Decide whether to move the pins to Ubuntu 24.04.5 (now published beside 24.04.4). The QEMU harness pins 24.04.4 Server EFI/kernel hashes, so a bump needs new hashes and a full rerun.
7. Wire live guided actions and evidence into the React/Tauri command bridge.
8. Replace hand-written JSON and CLI option parsing with `serde` and `clap`.
9. Replace the SQLite shell-out with `rusqlite` and migrate persisted reports into the journal schema.
10. Add resume/recover commands that consume persisted reports.
11. Expand the safe executor into feature-gated Windows/Linux families only after VM recovery tests pass.
12. Add package metadata and a release-signing plan.

## Backlog

Core:

- Expand `BootPlan` with real adapter capability mapping once platform adapters mature.
- Add richer signature-aware `VerificationResult` data.
- Expand `PlatformCapability` coverage as real adapters mature.
- Move current JSON report persistence into operation, step, artifact, backup, warning, confirmation, and log tables.
- Add file locking to prevent concurrent operations.
- Add richer resume/recover flow on top of persisted reports.
- Expand diagnostic bundles with SBOM/license/audit outputs once those commands exist.

CLI:

- Use `clap` for command parsing.
- Replace hand-written JSON helpers with `serde`.
- Add machine-readable exit codes.
- Keep stdout/stderr separation.
- Add tests around CLI JSON and `--yes` blocking behavior.

Profiles:

- Keep catalog profiles in `crates/nousb-installer-profiles/profiles/*.toml`.
- Replace the small dependency-free profile parser with `toml`/`serde` when dependency access is available.
- Add signature metadata fields.
- Add official-source provenance notes.

Platform adapters:

- Windows: detect BitLocker, WinRE, Secure Boot, firmware mode, admin status, disk layout.
- Linux: detect GRUB, systemd-boot, Secure Boot, ESP, LUKS, Btrfs, free space.
- macOS: excluded from the current objective; do not expand without an explicit scope change.

Desktop:

- Install and verify Vite/Tauri dependencies when network access is available.
- Replace the current static dashboard preview data with runtime calls once Tauri command wiring exists.
- Add recovery pack and logs screens to the React app.
- Use the same safety wording as the CLI.

Docs:

- Expand `docs/SAFETY_MODEL.md` with confirmation matrix.
- Expand `docs/THREAT_MODEL.md` with trust boundaries.
- Add VM test plan details.
- Add user guide screenshots after desktop UI is wired.

## Fresh Chat Start Prompt

Paste this into a new chat:

```text
We are continuing the NoUSB OS Switcher project in this repository (RevX).
Read START_HERE.md, TODO.md, docs/HANDOFF.md, AGENTS.md, README.md, and docs/MASTER_PROMPT.md first.
Keep default builds non-destructive.
Run cargo test --workspace before finalizing changes.
Continue from the "Next Best Steps" section in TODO.md.
```
