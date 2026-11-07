# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Host one-shot boot of a verified official Linux live installer (`nousb boot plan | arm | status | cleanup`). Arming exists only in builds with `real-windows-boot` or `real-linux-boot` and requires the typed phrase `BOOT ONCE INTO <profile>`. Windows uses `bcdedit` `{fwbootmgr} bootsequence`; Linux uses `efibootmgr --create-only` plus `--bootnext`. The persistent boot order is never changed, and any failed step rolls back every completed step.
- Live-boot recipe derived from the ISO's own GRUB configuration (casper and dracut families), with `iso-scan/filename=` and RAM copy when memory allows.
- Desktop "Boot once" view and Tauri commands for the same plan, status, arm, and cleanup flow (arm and cleanup only with the desktop `real-boot` feature).
- `docs/PHYSICAL_TESTING.md`, open-source licenses (Apache-2.0 OR MIT), security policy, code of conduct, contributing guide, and issue/PR templates.

- `scripts/vm/linux_host_boot_rehearsal.py`: a disposable KVM + OVMF rehearsal of the real Linux arm → one boot → return → cleanup cycle, with and without Secure Boot.

### Fixed

- `boot plan` reported `Ready: yes` on Linux hosts without `efibootmgr`, and arming then failed and rolled back. The plan now lists the missing tool as a blocker.
- The plan's copy step printed the staging path without a separator (`/bootNoUSB/...`) when the staging root had no trailing slash.
- `pnpm tauri build` failed because `@tauri-apps/api` (2.11) did not match the `tauri` crate (2.12). The npm package is now pinned to 2.12.3.

### Changed

- `nousb doctor` reports whether real boot adapters are compiled in.
- The checked-in desktop preview fixture no longer contains local file-system paths.

## [0.1.0]

- Safe planning, verified acquisition and staging, disposable-VM rehearsal evidence, and simulated execution. No host boot changes.
