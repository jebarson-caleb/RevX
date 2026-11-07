# VM One-Shot Boot and Recovery Rehearsal

This document defines the proof required before NoUSB may modify a real Windows or Linux boot path. macOS is outside the current objective.

## Current Status

`nousb vm rehearse <backend> <profile>` runs a deterministic boot-transaction state machine. It injects interruption after every transition and verifies all of these invariants:

- The original default boot entry never changes.
- The persistent boot order never changes.
- A pending one-shot selector is consumed or cleared.
- Temporary installer entries and staged assets are removed.
- If control reached the installer, recovery returns to the original default.
- The recovery backup remains available for audit.

The matrix contains one complete cycle and eight interruption cases:

1. Capture boot-state backup.
2. Stage verified assets on the virtual disk.
3. Register a temporary installer entry.
4. Select it for one boot.
5. Transfer control to the installer and consume the one-shot selector.
6. Observe the live payload in RAM.
7. Reboot to the original default.
8. Remove temporary state.

Run all supported backend models:

```sh
cargo run -p nousb -- vm doctor
cargo run -p nousb -- vm rehearse uefi-bootnext ubuntu-24.04-desktop
cargo run -p nousb -- vm rehearse windows-bcd-bootsequence ubuntu-24.04-desktop
cargo run -p nousb -- vm rehearse linux-systemd-boot-oneshot ubuntu-24.04-desktop
cargo run -p nousb -- vm rehearse linux-grub-reboot ubuntu-24.04-desktop
```

Reports are stored under `.nousb/vm-rehearsals/`. Every report states `real_vm_executed=false` and `host_boot_changes=false`. Passing the state-machine matrix is necessary but is not evidence that firmware, Secure Boot, an installer, or a particular computer will boot.

## Real disposable-VM evidence on the current Windows host

Hyper-V is installed, but the current non-elevated identity cannot query or create Hyper-V VMs. NoUSB therefore assembles QEMU 10.1.5 and OVMF from Alpine v3.23's signed repositories under `.nousb/tools/qemu-alpine-root` and runs it through the already-enabled `docker-desktop` WSL2 distribution. Nothing is installed into Windows system directories.

The runtime is reproducible from the repository:

```sh
cargo run -p nousb -- vm qemu plan-runtime
cargo run -p nousb -- vm qemu bootstrap-runtime "ASSEMBLE PROJECT-LOCAL QEMU RUNTIME"
```

`bootstrap-runtime` runs `apk --root` inside `docker-desktop` against the pinned v3.23 `main` and `community` repositories, verifying package signatures with that distribution's `/etc/apk/keys`. It installs `busybox`, `busybox-extras` (the `httpd` used by the full-RAM rehearsals), `qemu-system-x86_64~10.1.5`, `ovmf`, `efibootmgr`, `grub-efi`, `sfdisk`, `dosfstools`, and `mtools`. It then fails closed unless the runtime reports QEMU 10.1.5 and contains OVMF code/vars, `efibootmgr`, `busybox`, `grub-mkstandalone` with the x86_64-efi modules, and the ESP image tools. It writes `.nousb/tools/qemu-alpine-root.manifest.json` with the installed package versions and the SHA-256 of each signing key. Re-running is idempotent. It refuses to touch a non-empty directory that `apk` does not manage.

Keep the project (or at least `.nousb/`) outside a cloud-synced folder such as OneDrive: the runtime, the 3.2 GiB Server ISO, and every run's disk images live there. Run only one disposable rehearsal at a time. Two rehearsals started together on this host both blocked in WSL's 9p file bridge, so the one-shot harness now gives each scenario its own read-only firmware copy.

Preview and run the typed, disposable checks:

```sh
cargo run -p nousb -- vm qemu plan-smoke
cargo run -p nousb -- vm qemu smoke "RUN DISPOSABLE QEMU UEFI SMOKE"
cargo run -p nousb -- vm qemu plan-ubuntu-netboot
cargo run -p nousb -- vm qemu rehearse-ubuntu-netboot "RUN DISPOSABLE UBUNTU NETBOOT RAM REHEARSAL"
cargo run -p nousb -- vm qemu plan-ubuntu-full-ram
cargo run -p nousb -- vm qemu rehearse-ubuntu-full-ram "RUN DISPOSABLE UBUNTU FULL ISO RAM REHEARSAL"
cargo run -p nousb -- vm qemu plan-ubuntu-uefi-full-ram
cargo run -p nousb -- vm qemu rehearse-ubuntu-uefi-full-ram "RUN DISPOSABLE UBUNTU UEFI FULL ISO RAM REHEARSAL"
```

The UEFI smoke has real QMP evidence that QEMU reached `running` under OVMF. `query-block` showed only the read-only OVMF code image and a fresh project-local variables copy. It attached no OS installer, network, virtual disk, physical disk, or host boot state.

The Ubuntu rehearsal booted the official 24.04.4 netboot kernel and initrd far enough to observe the Linux banner and initramfs `init-premount` scripts. QMP returned an empty block-device list. This proves that the kernel and initrd executed from guest RAM, but it uses QEMU's direct-kernel path, bypasses UEFI, disables networking, and does **not** prove that the 3.2 GB server ISO or 6.2 GB desktop live payload reached RAM.

The direct full-RAM rehearsal closes the payload half of that gap. It boots the verified Server kernel/initrd with casper's `url=` flow, downloads the pinned 3.2 GiB Server ISO into initramfs, stops the isolated source server, and requires fresh systemd, Subiquity mount, and serial-console evidence after the stop. It is still a direct-kernel boot and therefore is not UEFI evidence.

The combined UEFI full-RAM rehearsal closes the firmware-to-payload gap in the disposable harness. A run-local read-only FAT source contains only the hash-verified official `BOOTX64.EFI`, GRUB, MokManager, kernel, initrd, and generated GRUB configuration. OVMF selects that source; Linux reports EDK II UEFI; QMP removes both the temporary boot device and its block node; casper saves and mounts the full verified ISO in RAM; the isolated HTTP source stops; and fresh Ubuntu, Subiquity, and `ttyS0` evidence follows. The final QMP block list contains only OVMF code and variable pflash devices. This proves full installer payload continuity after source removal, not an OS installation.

Real reports are stored under `.nousb/vm/qemu/*/report.json`; serial and QMP logs are stored beside each report. The successful combined evidence is in `.nousb/vm/qemu/ubuntu-uefi-full-ram-1784649708-5480/report.json`. The netboot tarball is deliberately labeled `official-https-observed-digest-transport-only-not-installable` because Canonical's signed 24.04.4 `SHA256SUMS` lists the desktop/server ISOs but not the netboot tarball. It is valid only for the earlier diskless rehearsal, never as an installation payload. The full-RAM runners instead verify the official Server ISO's exact size and SHA-256.

### Disposable current OS, real UEFI BootNext, fallback, and power-loss matrix

```sh
cargo run -p nousb -- vm qemu plan-current-os-baseline
cargo run -p nousb -- vm qemu rehearse-current-os-baseline "RUN DISPOSABLE CURRENT OS UEFI BASELINE"
cargo run -p nousb -- vm qemu plan-current-os-one-shot
cargo run -p nousb -- vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX"
cargo run -p nousb -- vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX" complete-cycle
cargo run -p nousb -- vm qemu plan-current-os-one-shot linux-grub-reboot
cargo run -p nousb -- vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX" linux-grub-reboot
cargo run -p nousb -- vm qemu rehearse-current-os-one-shot "RUN DISPOSABLE CURRENT OS UEFI ONE-SHOT MATRIX" uefi-bootnext full-ram-installer
```

Optional arguments, in any order: a backend (`uefi-bootnext`, the default, or `linux-grub-reboot`), an installer mode (`forced-failure`, the default, or `full-ram-installer`), and one scenario name. `windows-bcd-bootsequence` and `linux-systemd-boot-oneshot` fail closed: the first needs a disposable Windows guest image, and the second needs a systemd-boot build, which this Alpine runtime does not package.

The one-shot harness builds a disposable machine with three virtio disks at fixed PCI slots:

- `/dev/vda`: an ext4 disposable "current OS" (busybox userland copied from the runtime, plus `efibootmgr`), booted by the pinned Ubuntu kernel/initrd with `boot=local`.
- `/dev/vdb`: the current OS's own GPT ESP image (random disk/partition GUIDs) carrying a standalone GRUB from the runtime's signed `grub-efi` package. Its configuration lives in GRUB's memdisk, and it is the only device with a firmware boot index, so OVMF makes it the `BootOrder` default.
- `/dev/vdc`: a read-only installer ESP with the pinned official `BOOTX64.EFI` (shim), `grubx64.efi`, `mmx64.efi`, kernel, initrd, and `/.disk/info`. The kernel command line carries `nousb.oneshot=installer` and deliberately fails with a panic and reboot, to model an installer failure.

Each scenario gets fresh copies of the disk, the OVMF variable store, and the OVMF code. The guest runs a persisted state machine:

1. Record `BootCurrent`/`BootOrder`.
2. `efibootmgr -C` creates `NoUSB-OneShot` *outside* `BootOrder`.
3. `efibootmgr -n` sets `BootNext`, and the guest reboots.
4. Firmware consumes `BootNext`, and the installer chain runs once and panics.
5. Firmware falls back to the default, and the current OS records the return.
6. The current OS clears any pending `BootNext` and deletes the temporary entry.
7. A final boot verifies `BootOrder`, `BootCurrent`, and the absence of `BootNext` and temporary entries.

Every step syncs before printing its marker, and the host cuts power with QMP `quit` the moment a scenario's marker appears.

The host evaluator (`evaluate_one_shot_serial`, unit-tested without a VM) fails a scenario unless all of these hold:

- Firmware's own `BdsDxe: starting Boot<entry>` line and the installer kernel each appear exactly once (zero times when power is cut before `BootNext` is written), and in that order.
- `BootOrder` never changes.
- Every return to the current OS has the baseline `BootCurrent` and no pending `BootNext`.
- The single final verification passes with zero temporary entries.
- The scheduled power cut was actually applied.

A cycle that loops into the installer, stops at a `grub>` or firmware shell prompt, or exceeds 15 minutes fails immediately.

Three harness bugs were found and fixed on the way to a passing run, and each is now guarded:

- The live-server initrd defaults to `BOOT=casper`. The current OS needs `boot=local`; without it, the baseline rehearsal stalled at "Unable to find a medium containing a live file system".
- The ISO GRUB does not set `$cmdpath` and read the *other* ESP's configuration. The current OS now has its own standalone GRUB with an embedded configuration.
- QEMU vvfat disks all share MBR signature `0xBE1AFDFA` and the same geometry, so OVMF resolved the short-form `HD(1,MBR,0xBE1AFDFA,…)` boot path to the wrong disk. Real disks have unique identifiers, and the current OS ESP is now a GPT image.

In the second and third cases, firmware honoured `BootNext` while the wrong kernel ran; the evaluator caught this as a `BootCurrent` mismatch and a missing installer boot.

A fourth bug was in the evaluator itself. A power cut can land between the kernel's early `Command line:` echo and its later `Kernel command line:` echo, so installer boots are now counted per `Linux version` banner.

Result on the current Windows host (QEMU 10.1.5 TCG, OVMF from Alpine `ovmf-0.0.202508`, Ubuntu 24.04.4 Server shim/GRUB/kernel 6.8.0-100, efibootmgr 18): the full matrix passed in 15m54s with `one_shot_selection_proven=true` (named `uefi_bootnext_proven` before the GRUB backend existed), `installer_fallback_proven=true`, and `power_loss_matrix_complete=true`. In every scenario, the baseline was `BootCurrent=0002` and `BootOrder=0002,0000,0001`. The temporary entry was `Boot0003` at `HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)/\EFI\BOOT\BOOTX64.EFI`.

| Scenario | Power cycles | Installer boots | Result |
| --- | --- | --- | --- |
| `complete-cycle` | 1 | 1 | pass |
| `after-temporary-entry-created` | 2 | 0 (transaction aborted, stale entry removed) | pass |
| `after-bootnext-armed` | 2 | 1 (firmware honoured `BootNext` on power-on) | pass |
| `during-installer-boot` | 2 | 1 (`BootNext` already consumed; power-on went to the default) | pass |
| `after-return-before-cleanup` | 2 | 1 | pass |
| `after-temporary-entry-deleted` | 2 | 1 (idempotent cleanup found nothing left) | pass |

Each scenario directory holds `scenario.json`, every power cycle's serial/QMP/stderr logs, and the final OVMF variable store. `report.json` sits at the run root. Once a scenario passes, its 512 MiB root disk, 256 MiB ESP copy, and firmware-code copy are deleted; a fully passing run also deletes its templates. Failing runs keep everything. (Repeated matrices filled this host's disk before that cleanup existed.)

After the guest script was refactored into backend-neutral `selector_*` functions, the UEFI matrix was re-run (run `current-os-one-shot-uefi-bootnext-1792634219-8212`): all six scenarios passed again, `power_loss_matrix_complete=true`.

#### GRUB `next_entry` backend

The same state machine runs with `grub-reboot` semantics instead of firmware variables. The current OS's standalone GRUB loads `grubenv` from its own writable GPT ESP. If `next_entry` is set, GRUB makes it the default, clears it with `save_env`, and only then boots it; `fallback=current` covers a broken entry. The guest edits the ESP with mtools, because the disposable root has no vfat module: the temporary entry is `/grub/nousb-oneshot.cfg`, and `grub-editenv` sets `next_entry`. The evaluator requires GRUB's own `booting=nousb-oneshot` line (not a firmware `BdsDxe` line) exactly once, and requires the firmware `BootCurrent` to stay the current OS in every boot.

One more harness bug surfaced here. OVMF connects only devices in QEMU's boot order, so GRUB could not see the installer disk (`no such device: /casper/vmlinuz`). That GRUB still cleared `next_entry` and fell back, and the evaluator failed the run for the missing installer boot. The GRUB backend now gives the installer disk `bootindex=1`, after the current OS.

Result (run `current-os-one-shot-linux-grub-reboot-1792632999-7552`, 18m14s): all six scenarios passed, `power_loss_matrix_complete=true`. The baseline and final `BootOrder` were both `0002,0003,0000,0001`, `next_entry` was absent after every return, and installer boots per scenario matched the UEFI table above (0 when power was cut before `next_entry` was written, otherwise 1).

This evidence proves real UEFI `BootNext` semantics, firmware fallback to an unchanged default, and transaction cleanup after power loss, all with `efibootmgr` in a disposable guest. It does not prove Windows BCD `bootsequence`, systemd-boot, or behaviour on any physical firmware. Secure Boot and the full-RAM installer mode are covered below.

## Backend Semantics

### UEFI BootNext

UEFI `BootNext` names one `Boot####` option to try first on the next boot. Firmware deletes `BootNext` before transferring control, then returns to `BootOrder` on later boots. This is the strongest cross-vendor primitive when firmware variables are usable, but creating the temporary `Boot####` option and staging a trusted EFI loader remain platform-specific operations.

### Windows BCD bootsequence

Microsoft documents `bcdedit /bootsequence` as a one-time boot-manager sequence. NoUSB may eventually use it only after exporting the BCD store and proving that a temporary installer entry can chain into signed EFI assets. BCDEdit requires administrative rights, and Microsoft notes that BitLocker or Secure Boot handling may be required. The default build does not call BCDEdit.

### systemd-boot LoaderEntryOneShot

`bootctl set-oneshot ID` selects a Boot Loader Specification entry only for the next boot. A future adapter must place the kernel, initrd, entry file, and ISO on the virtual ESP/XBOOTLDR, preserve the original entry, and remove the temporary files after fallback. The default build does not call `bootctl set-oneshot`.

### GRUB next_entry

GRUB supports saved and next-boot entries through `grub-reboot`, but the official manual warns that one-shot configurations need a known-good fallback and can stop at GRUB when the new entry itself is invalid. This backend therefore needs stricter VM failure tests than UEFI BootNext or systemd-boot. The default build does not call `grub-reboot`.

## Remaining real-VM proof before host boot work

The isolated QEMU engine, OVMF startup, official EFI asset chain, and full Server installer continuity in RAM after temporary-source removal are now proven. A host boot adapter still must not be implemented until the remaining recovery test satisfies all of these conditions:

- No physical disk, host ESP, host firmware variable store, or host boot configuration is attached writable.
- The VM disk and writable UEFI variable store are disposable copies.
- The original guest OS boots successfully before testing.
- The pinned and verified assets continue to pass exactly as they do in the combined rehearsal.
- A real one-shot entry is selected without changing the disposable guest's persistent default/order.
- The temporary boot source can be removed while Ubuntu's full installer payload remains available, as already proven in the combined rehearsal.
- Power loss is injected after every transaction step and the next boot returns to the original guest OS.
- The test captures serial console, firmware variable, boot-entry, artifact, and cleanup evidence.
- Secure Boot is enabled and the complete boot chain is accepted, or the product blocks that host with a precise explanation.
- Guest acquisition uses authenticated transport, or its threat model and verified-digest handoff are explicitly accepted.

The disposable current OS, real one-shot UEFI selection, reboot/failure, original-OS fallback, and interruption cleanup are now proven by the one-shot matrix above (UEFI `BootNext` only). What remains is joining that matrix to the already-proven full installer in RAM in one run, Secure Boot, authenticated guest transport, and equivalent matrices for Windows BCD `bootsequence`, systemd-boot `LoaderEntryOneShot`, and GRUB `next_entry`. Until those pass, `real-windows-boot` and `real-linux-boot` remain disabled. Full-RAM combined reports may truthfully set `full_installer_payload_in_ram=true`, while `secure_boot_enabled`, `guest_transport_https`, and `fallback_boot_observed` remain false.

## Primary References

- [UEFI 2.11 Boot Manager and BootNext](https://uefi.org/specs/UEFI/2.11/03_Boot_Manager.html)
- [Microsoft BCDEdit /bootsequence](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--bootsequence)
- [systemd bootctl set-oneshot](https://www.freedesktop.org/software/systemd/man/latest/bootctl.html)
- [systemd-boot and automatic fallback](https://www.freedesktop.org/software/systemd/man/latest/systemd-boot.html)
- [GNU GRUB manual](https://www.gnu.org/software/grub/manual/grub/grub.html)
- [QEMU system invocation and firmware boot](https://www.qemu.org/docs/master/system/invocation.html)
- [QEMU direct Linux boot](https://www.qemu.org/docs/master/system/linuxboot.html)
- [Ubuntu amd64 netboot installer flow](https://documentation.ubuntu.com/server/how-to/installation/how-to-netboot-the-server-installer-on-amd64/)
- [Ubuntu 24.04.4 release images and netboot bundle](https://releases.ubuntu.com/24.04/)
- [Ubuntu casper `toram`](https://manpages.ubuntu.com/manpages/noble/man7/casper.7.html)
