# Testing

Run:

```sh
cargo test --workspace
```

Open `apps/desktop/preview.html` directly in a browser to inspect the static dashboard preview. It does not require a dev server.

Current unit coverage validates:

- Critical risk classification for replace-OS plans.
- BootPlan invariants for one-time boot and permanent boot-order safety.
- Typed confirmation gates.
- Unknown profile rejection.
- Built-in catalog sanity.
- Embedded TOML profile validation.
- Fake Windows BitLocker/Secure Boot preflight warnings.
- Fake Linux LUKS/Btrfs low-space manual intervention.
- Fake macOS Apple Silicon/FileVault policy warnings.
- CLI smoke tests for fake scenario planning and JSON output.
- Simulated executor completion, interruption, failure, and rollback behavior.
- CLI smoke tests for interrupted simulation and rollback JSON.
- Persistence tests for saving, listing, and showing execution reports.
- Diagnostic bundle export and secret-like log redaction tests.
- Delivery assessment for Windows-to-Ubuntu host-staged RAM boot.
- Explicit macOS delivery exclusion and disabled universal no-USB claims.
- Pinned Ubuntu 24.04.4 and Fedora 44 artifact manifests.
- Fail-closed handling of the vendor-mediated Windows 11 ISO.
- Cross-platform in-process SHA-256 verification and atomic partial-file promotion.
- Staging path traversal and platform-separator rejection.
- CLI manifest JSON and unavailable-manifest failure behavior.
- A deterministic synthetic ISO9660 image covering verification, multi-sector directory lookup, version/trailing-dot normalization, kernel/initrd extraction, per-asset hashes, and final non-executable bundle metadata.
- Guided TUI assessment/manifest/plan behavior and rejection of an incorrect typed download confirmation.
- A process-level scripted `nousb tui` smoke test using the real host inspection adapter.
- Nine-scenario VM rehearsal matrices for each of four one-shot backends, including interruption after every transaction transition.
- Backend-specific selector evidence for UEFI BootNext, BCD bootsequence, LoaderEntryOneShot, and GRUB next-entry.
- Project-local VM rehearsal report persistence and CLI/runtime-doctor smoke tests.
- Exact QEMU 11.0.0 Windows runtime manifest size/SHA-512 and project-local cache-path validation.
- Disposable QEMU/OVMF plan invariants: no network, physical disk, host boot change, or implicit installer attachment.
- Ubuntu netboot, direct full-RAM, and combined UEFI full-RAM rehearsal plans with truthful transport, firmware, disk, and host-mutation constraints.
- One-shot serial-evidence evaluator: complete cycle, power loss before `BootNext` (no installer boot), repeated installer boot, firmware starting the entry but the wrong kernel running, pending `BootNext` after return, changed `BootOrder`, leftover entries, guest errors, and a missing power cut.
- Guest state-machine and GRUB configuration invariants: every power-cut trigger exists in the guest script, and installer/current-OS kernels and roots never cross.
- CLI gating for `vm qemu plan-runtime`, `bootstrap-runtime`, `plan-current-os-one-shot`, and `rehearse-current-os-one-shot` (exact phrases, unknown scenarios rejected, Windows-only commands fail closed elsewhere).

Current-host manual integration checks, each protected by an exact typed phrase:

```sh
cargo run -p nousb -- vm qemu smoke "RUN DISPOSABLE QEMU UEFI SMOKE"
cargo run -p nousb -- vm qemu rehearse-ubuntu-netboot "RUN DISPOSABLE UBUNTU NETBOOT RAM REHEARSAL"
cargo run -p nousb -- vm qemu rehearse-ubuntu-full-ram "RUN DISPOSABLE UBUNTU FULL ISO RAM REHEARSAL"
cargo run -p nousb -- vm qemu bootstrap-runtime "ASSEMBLE PROJECT-LOCAL QEMU RUNTIME"
cargo run -p nousb -- vm qemu rehearse-ubuntu-uefi-full-ram "RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL"
cargo run -p nousb -- vm qemu rehearse-current-os-baseline "RUN DISPOSABLE CURRENT OS UEFI BASELINE"
cargo run -p nousb -- vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX"
```

The first check records OVMF/QMP startup and a firmware-only block list. The second records the Ubuntu kernel banner, initramfs scripts, and an empty QMP block list. The third copies the pinned full Server ISO into initramfs, stops its source, and requires fresh installer evidence afterward. The fourth combines that full-RAM proof with OVMF, verified official EFI assets, QMP removal of the temporary boot source, and a final firmware-only block list. All are disposable and attach no physical disk or host boot state. The combined report deliberately keeps `secure_boot_enabled`, `guest_transport_https`, and `fallback_boot_observed` false. The one-shot matrix boots a disposable current OS, arms a real UEFI `BootNext` with `efibootmgr`, lets the official installer chain run once and fail, and checks firmware fallback and cleanup after a power cut at each of five transaction points; see `docs/VM_ONE_SHOT.md`. Run these rehearsals one at a time.

CI runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, and the test suite on Ubuntu and Windows. The Windows job compiles and lints the WSL/QEMU harness, but never starts a VM because the runtime and ISO are absent.

Future integration tests should use fake adapters for Windows UEFI, BitLocker, Secure Boot, Linux GRUB/systemd-boot, LUKS, Btrfs, low-space systems, corrupt ISOs, checksum mismatch, interrupted downloads, real distribution ISO extraction checks, and rollback after partial failure. macOS remains out of scope for the current objective.

Host one-shot boot tests (no real tool ever runs):

- Live-boot recipe derivation from official GRUB configurations (casper and dracut), and refusal of variables, traversal, and unknown families.
- Generated GRUB configuration: `iso-scan/filename=` placed before `---`, RAM copy only when memory allows.
- Planning reports every blocker (missing ISO, no real backend, BIOS, not elevated, encrypted or unknown staging volume, NTFS with dracut).
- A full arm, refusal of a second arm, and cleanup against `FakeHostBootBackend`. The ESP's other files and the boot order stay untouched.
- Injected failure at backup, ESP mount, entry creation, and arming each rolls back completely.
- An existing `EFI/NoUSB` directory is never overwritten.
- Scripted `bcdedit` sequence: `/copy {bootmgr}`, `/set path`, `{fwbootmgr} bootsequence`, cleanup, and removal from `displayorder` if Windows adds the copy.
- Scripted `efibootmgr` sequence: `--create-only`, `--bootnext`, `--delete-bootnext`, idempotent `--delete-bootnum`.

Physical testing is manual and documented in [PHYSICAL_TESTING.md](PHYSICAL_TESTING.md).

No CI test may modify real boot configuration.
