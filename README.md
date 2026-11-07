# NoUSB OS Switcher

Boot an official OS installer once, without a USB stick, and always fall back to the OS you already have.

NoUSB downloads a pinned official installer image, verifies its exact size, SHA-256, and vendor signature, and plans every change before making it. On a Windows or Linux UEFI PC it can then select that installer for **exactly one boot**, using the firmware's own one-shot mechanism (UEFI `BootNext` / Windows `bcdedit bootsequence`). Your default boot entry and boot order are never changed, so the next reboot returns to your current OS.

> **Status: pre-release, physical testing.** Default and release builds are non-destructive: they inspect, verify, plan, and simulate, but cannot change boot settings. Real one-shot boot needs an explicit `real-windows-boot` / `real-linux-boot` build, an elevated shell, and a typed confirmation phrase. Read [docs/PHYSICAL_TESTING.md](docs/PHYSICAL_TESTING.md) before trying it, and keep a backup.

## What works today

| | Default build | `real-*-boot` build |
| --- | --- | --- |
| Inspect firmware, Secure Boot, encryption, ESP, boot entries (read-only) | yes | yes |
| Download and verify Ubuntu 24.04.4 and Fedora 44 (size, SHA-256, OpenPGP) | yes | yes |
| `nousb boot plan`: exact files, firmware entry, GRUB config, blockers | yes | yes |
| `nousb boot arm`: one-shot boot into the live installer | refused | Windows/Linux UEFI, typed phrase |
| `nousb boot cleanup`: remove the entry and every staged file | refused | yes |
| Guided TUI (`nousb tui`) and desktop app (Tauri) | yes | desktop needs `real-boot` |
| Disposable-VM evidence (QEMU/OVMF one-shot, fallback, power-loss matrix) | yes | yes |

Supported directions are Windows or Linux (UEFI) to an official Linux live installer (Ubuntu casper, Fedora dracut). Windows 11 as a target, legacy BIOS, encrypted staging volumes, and macOS are not supported; [docs/PHYSICAL_TESTING.md](docs/PHYSICAL_TESTING.md) explains why. NoUSB never partitions, formats, or installs anything itself. Any installation happens in the official installer, by your choice.

## Physical testing, short version

```sh
cargo build --release -p nousb --features real-windows-boot     # or real-linux-boot
nousb image download ubuntu-24.04-desktop
nousb boot plan ubuntu-24.04-desktop                             # must say "Ready: yes"
nousb boot arm ubuntu-24.04-desktop "BOOT ONCE INTO ubuntu-24.04-desktop"   # elevated
# reboot, try the live system, reboot back, then:
nousb boot cleanup "CLEAN UP NOUSB BOOT"
```

## Quick Start

```sh
cargo run -p nousb -- doctor
cargo run -p nousb -- tui
cargo run -p nousb -- system inspect
cargo run -p nousb -- catalog list
cargo run -p nousb -- catalog validate
cargo run -p nousb -- workflow assess ubuntu-24.04-desktop
cargo run -p nousb -- workflow assess-fake windows-bitlocker ubuntu-24.04-desktop
cargo run -p nousb -- --json image manifest ubuntu-24.04-desktop
cargo run -p nousb -- image probe ubuntu-24.04-desktop
cargo run -p nousb -- vm doctor
cargo run -p nousb -- vm rehearse windows-bcd-bootsequence ubuntu-24.04-desktop
cargo run -p nousb -- vm qemu plan-smoke
cargo run -p nousb -- vm qemu plan-ubuntu-netboot
cargo run -p nousb -- vm qemu plan-ubuntu-full-ram
cargo run -p nousb -- vm qemu plan-ubuntu-uefi-full-ram
cargo run -p nousb -- vm qemu plan-runtime
cargo run -p nousb -- vm qemu plan-current-os-one-shot
cargo run -p nousb -- plan boot-once ubuntu-24.04-desktop
cargo run -p nousb -- system inspect-fake windows-bitlocker
cargo run -p nousb -- plan-fake linux-luks-low-space boot-once ubuntu-24.04-desktop
cargo run -p nousb -- --interrupt-after 2 simulate boot-once ubuntu-24.04-desktop
cargo run -p nousb -- --rollback --interrupt-after 2 simulate boot-once ubuntu-24.04-desktop
cargo run -p nousb -- reports list
cargo run -p nousb -- diagnostics export
cargo run -p nousb -- dashboard export
cargo run -p nousb -- --json plan boot-once ubuntu-24.04-desktop
cargo run -p nousb -- --dry-run plan replace-os ubuntu-24.04-desktop
cargo run -p nousb -- recovery-pack create
```

## Resuming Work

Start with `START_HERE.md`, then `TODO.md` and `docs/HANDOFF.md`. They capture the current project state, verified commands, next steps, and a fresh-chat prompt.

## Desktop Preview

Run `cargo run -p nousb -- tui` for the cross-platform guided terminal application. It provides host summary, profile selection, no-USB feasibility assessment, official artifact manifests and probes, typed download/staging gates, boot-plan previews, and read-only display of disposable VM plans/evidence. It deliberately exposes no host install or boot executor.

Open `apps/desktop/preview.html` in a browser for a dependency-free dashboard preview. It mirrors the current safe CLI/TUI surface: catalog validation, fake scenarios, plan previews, persisted reports, and diagnostic bundles.

## Project Layout

- `crates/nousb-core`: operation model, planner, risk gates, catalog, journal, recovery pack.
- `crates/nousb-cli`: working CLI.
- `crates/nousb-platform-*`: read-only Windows/Linux inventory adapters plus the excluded macOS scaffold.
- `crates/nousb-installer-profiles`: versioned TOML installer profiles and catalog facade.
- `apps/desktop`: Tauri/React source scaffold plus dependency-free dashboard preview.
- `docs`: architecture, safety, testing, recovery, and the original master prompt.

## Safety Status

Default and release builds are a planning and audit tool. Real boot changes exist only in opt-in builds with these features:

- `real-windows-boot`
- `real-linux-boot`
- `real-macos-boot`
- `destructive-tests`
- `technician-mode`

## Current CLI

```text
nousb tui
nousb system inspect
nousb system inspect-fake <scenario>
nousb catalog list
nousb catalog validate
nousb workflow assess <profile>
nousb workflow assess-fake <scenario> <profile>
nousb image manifest <profile>
nousb image probe <profile>
nousb image verify-signature <profile>
nousb image download <profile>
nousb image verify-profile <profile> <path>
nousb image verify <path> <sha256>
nousb staging inspect <profile> <path>
nousb staging create <profile> <path>
nousb vm doctor
nousb vm rehearse <backend> <profile>
nousb vm qemu manifest
nousb vm qemu acquire
nousb vm qemu plan-runtime
nousb vm qemu bootstrap-runtime "ASSEMBLE PROJECT-LOCAL QEMU RUNTIME"
nousb vm qemu plan-smoke
nousb vm qemu smoke "RUN DISPOSABLE QEMU UEFI SMOKE"
nousb vm qemu plan-ubuntu-netboot
nousb vm qemu rehearse-ubuntu-netboot "RUN DISPOSABLE UBUNTU NETBOOT RAM REHEARSAL"
nousb vm qemu plan-ubuntu-full-ram
nousb vm qemu rehearse-ubuntu-full-ram "RUN DISPOSABLE UBUNTU FULL ISO RAM REHEARSAL"
nousb vm qemu plan-ubuntu-uefi-full-ram
nousb vm qemu rehearse-ubuntu-uefi-full-ram "RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL"
nousb vm qemu plan-current-os-baseline
nousb vm qemu rehearse-current-os-baseline "RUN DISPOSABLE CURRENT OS UEFI BASELINE"
nousb vm qemu plan-current-os-one-shot
nousb vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX" [scenario]
nousb boot plan <profile> [--iso <path>] [--staging-root <volume-root>]
nousb boot arm <profile> "BOOT ONCE INTO <profile>"
nousb boot status
nousb boot cleanup "CLEAN UP NOUSB BOOT"
nousb plan boot-once <profile>
nousb plan dual-boot <profile>
nousb plan replace-os <profile>
nousb plan reinstall-current-os <profile>
nousb plan-fake <scenario> <plan-kind> <profile>
nousb simulate <plan-kind> <profile>
nousb simulate-fake <scenario> <plan-kind> <profile>
nousb reports list
nousb reports show <plan-id>
nousb reports recover <plan-id>
nousb resume <plan-id>
nousb diagnostics export
nousb dashboard export
nousb execute <plan-kind> <profile>
nousb rollback <operation-id>
nousb recovery-pack create
nousb logs export
nousb journal migrate
nousb doctor
```

`execute` remains intentionally blocked; the host one-shot flow is `nousb boot`. Image acquisition is enabled only for profiles with a stable official HTTPS URL, pinned byte size, and pinned SHA-256. Ubuntu 24.04.4 and Fedora 44 meet that rule. Windows 11 remains vendor-mediated because Microsoft generates time-limited consumer ISO links; NoUSB refuses to invent or cache an unpinned URL.

The TUI adds a separate typed phrase before starting a multi-gigabyte download (`DOWNLOAD <profile>`) and before creating a verified bundle (`STAGE <profile>`). Neither phrase enables boot execution.

Press `v` in the TUI, or use `vm rehearse`, to run the one-shot boot/fallback state-machine matrix. It tests UEFI BootNext, Windows BCD bootsequence, systemd-boot one-shot, or GRUB next-entry semantics without starting a VM or touching host boot state. Press `r` to display the separate real disposable-VM plans and saved evidence.

On the current Windows host, typed QEMU commands now prove the combined UEFI and full-installer RAM path. OVMF selected a read-only FAT source built from SHA-256-verified Ubuntu 24.04.4 Server EFI/kernel/initrd assets; QMP then deleted that USB/vvfat source. Casper downloaded the exact 3,405,469,696-byte pinned ISO into guest RAM, the owned HTTP source was stopped, and Ubuntu, the Subiquity payload, and the installer tty continued afterward. Final QMP storage contained only immutable OVMF code and a disposable variables copy. The run used no physical or virtual install disk and made no host boot change. A separate disposable matrix (`vm qemu rehearse-current-os-one-shot`) proves real UEFI `BootNext` selection of the official installer chain exactly once, firmware fallback to an unchanged default, and cleanup after a power cut at every transaction step. Secure Boot, guest-side HTTPS, and joining that matrix to the full-RAM installer remain unproven; see `docs/VM_ONE_SHOT.md`.

Downloads are stored under `.nousb/artifacts/<profile>/`. A mismatch never replaces the final artifact, and resumable `.part` data is retained for inspection. `staging create` first re-verifies the entire ISO, then extracts only profile-declared assets under `.nousb/staging/`; the resulting bundle records `execution_enabled=false` and cannot select a boot entry.

`workflow assess` compares the host and installer profile against host-staged RAM boot, GRUB loopback, Windows Setup/WinPE, UEFI HTTP Boot, and vendor-firmware recovery routes. It is a feasibility report, not an executor. See `docs/BOOT_DELIVERY.md` for the design boundary and primary references.

Global options:

```text
--json       Print machine-readable JSON where supported
--dry-run    Mark plan output as a dry run
--yes        Only allowed for low-risk actions; never bypasses typed confirmation
--interrupt-after <count>
--fail-step <step-id>
--rollback   Roll back the simulated report
```

In the default build, `nousb execute <plan-kind> <profile>` creates the requested plan and then refuses execution through the safe executor gate. Critical plans reject `--yes` before any execution path is considered.

Simulation reports are saved under `.nousb/reports/` and can be listed or shown later with `nousb reports list` and `nousb reports show <plan-id>`.

Diagnostic bundles are saved under `.nousb/diagnostics/` and include redacted project-local logs, saved reports, catalog metadata, and safe host inventory.

Dashboard data can be exported with `nousb dashboard export`; a portable preview fixture is checked in at `apps/desktop/preview-data.json`.

Fake scenarios:

```text
windows-bitlocker
linux-luks-low-space
```

macOS code remains an excluded compatibility scaffold and is not part of the current Windows/Linux objective.

## Contributing, security, and license

- [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md) (report vulnerabilities privately).
- [CHANGELOG.md](CHANGELOG.md) and [docs/RELEASE.md](docs/RELEASE.md) for release and signing rules.

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

NoUSB is provided without warranty. Changing how a computer boots can leave it temporarily unbootable; keep backups and a recovery medium for anything you cannot afford to lose.
