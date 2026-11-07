# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Host one-shot boot of a verified official Linux live installer (`nousb boot plan | arm | status | cleanup`). Arming exists only in builds with `real-windows-boot` or `real-linux-boot` and requires the typed phrase `BOOT ONCE INTO <profile>`. Windows uses `bcdedit` `{fwbootmgr} bootsequence`; Linux uses `efibootmgr --create-only` plus `--bootnext`. The persistent boot order is never changed, and any failed step rolls back every completed step.
- Live-boot recipe derived from the ISO's own GRUB configuration (casper and dracut families), with `iso-scan/filename=` and RAM copy when memory allows.
- Desktop "Boot once" view and Tauri commands for the same plan, status, arm, and cleanup flow (arm and cleanup only with the desktop `real-boot` feature).
- `docs/PHYSICAL_TESTING.md`, open-source licenses (Apache-2.0 OR MIT), security policy, code of conduct, contributing guide, and issue/PR templates.

### Changed

- `nousb doctor` reports whether real boot adapters are compiled in.
- The checked-in desktop preview fixture no longer contains local file-system paths.

## [0.1.0]

- Safe planning, verified acquisition and staging, disposable-VM rehearsal evidence, and simulated execution. No host boot changes.
