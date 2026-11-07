# Safety Model

The core rule is simple: NoUSB must never silently destroy, wipe, resize, repartition, overwrite, decrypt, encrypt, or replace anything.

Every high-risk operation requires:

- Preflight inspection.
- Dry-run preview.
- Recovery pack.
- Clear warning text.
- Typed confirmation for high and critical risk.
- Rollback notes where automatic rollback is impossible.

Default and release builds are non-destructive. They write only project-local logs, verified downloads, staging bundles, and recovery-pack metadata.

The only real boot change is the host one-shot boot (`nousb boot arm`), compiled only with `real-windows-boot` / `real-linux-boot`. It requires an exact typed phrase (`BOOT ONCE INTO <profile>`), refuses any plan with blockers, backs up firmware entries and BCD first, never overwrites existing files, never changes the default entry or persistent boot order, journals every step to `.nousb/host-boot/state.json`, and rolls back every completed step on failure. See [PHYSICAL_TESTING.md](PHYSICAL_TESTING.md).

Critical actions include replacing the current OS, modifying permanent boot order, touching EFI System Partition files, modifying BCD, modifying GRUB/systemd-boot, suspending disk encryption, and booting unverified images.

## BootPlan Invariants

Every operation plan carries a `BootPlan` with these safe defaults:

- Prefer one-time boot or temporary boot with fallback.
- Keep the current OS as the default boot target.
- Disallow permanent boot-order changes.
- Require boot metadata backups before any future real adapter executes.
- Provide manual firmware boot-menu fallback instructions.

## Confirmation Matrix

| Risk | Simple `--yes` | Typed confirmation | Default execution |
| --- | --- | --- | --- |
| Info | Allowed when no confirmation is required | Not required | Refused unless a future safe executor supports it |
| Low | Allowed for simple confirmations | Optional | Refused unless a future safe executor supports it |
| Medium | Not allowed | Required when configured | Refused |
| High | Not allowed | Required | Refused |
| Critical | Not allowed | Required | Refused |
