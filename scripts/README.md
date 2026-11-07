# Scripts

Development helpers belong here. Scripts must not modify boot configuration unless they are explicit future test harnesses gated behind destructive test flags.


- `vm/linux_host_boot_rehearsal.py`: runs the `real-linux-boot` binary inside a disposable KVM + OVMF guest (throwaway qcow2 overlay and variable store; nothing from the host is attached writable). See `docs/PHYSICAL_TESTING.md`.
