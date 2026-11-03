# Platform Compatibility

| Platform | Current support | Future adapter scope |
| --- | --- | --- |
| Windows 10/11 UEFI | Read-only UEFI/Secure Boot, non-admin memory and space, optional BitLocker hints, non-admin ESP and WinRE partition detection, delivery assessment, and current-host disposable WSL2/QEMU proofs: UEFI boot into a full Ubuntu Server installer held in RAM, plus real UEFI BootNext selection, fallback, and power-loss cleanup in a disposable guest | BCD export (needs elevation), firmware boot-entry reads, BCD bootsequence one-shot/fallback recovery, staged signed EFI/Linux boot, WinPE RAM disk |
| Linux UEFI | Read-only memory, space, Secure Boot, crypttab, ESP mount and vendor directories, GRUB/systemd-boot hints, firmware `BootOrder`/`BootCurrent`/`BootNext` and `Boot####` targets (local, PXE, HTTP) from efivarfs, and delivery assessment | GRUB loopback, kernel/initrd RAM live boot, systemd-boot entries, efibootmgr BootNext |
| Intel macOS | Safe inspection scaffold | Apple-supported `startosinstall`, `diskutil`, and `bless` workflows |
| Apple Silicon macOS | Guidance only | Supported workflows only; no boot policy bypass |
| Legacy BIOS | Not implemented | Lower-priority compatibility mode |

Default builds must not perform real boot changes.

The disposable Windows-host QEMU path is a development harness, not a portability guarantee: it currently depends on an existing `docker-desktop` WSL2 distribution. It proves a combined OVMF/official-EFI/full-ISO-in-RAM path, but its one-shot matrix proves UEFI `BootNext` and fallback with `efibootmgr` in a disposable guest, but it does not yet prove Secure Boot, guest-side HTTPS, or real firmware integration. Native Linux QEMU support and a redistributable Windows runtime deployment flow remain future work. The TUI/planner stay cross-platform even when that harness is unavailable.

The Windows adapter intentionally does not request elevation during inspection. If BitLocker status is unavailable to the current process it remains `Unknown`; the TUI does not infer that encryption is disabled. Firmware boot entries and BCD likewise stay explicitly unknown on Windows without elevation; `system inspect` lists every such unknown under `boot_hint: unknown:`.

UEFI HTTP Boot is an optional firmware capability, not a baseline guarantee. Legacy BIOS, machines without usable preboot networking, and systems whose current disk cannot safely hold staging assets require a different recovery path. macOS is excluded from the active product objective even though its safe scaffold remains in the workspace.

