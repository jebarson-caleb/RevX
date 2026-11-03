# NoUSB OS Switcher Agent Notes

Build safety first. The default workspace must remain non-destructive and must not modify boot entries, bootloader files, partitions, encryption settings, firmware variables, or installer media without explicit feature flags and typed confirmation gates.

## Commands

- Format: `cargo fmt --all`
- Test: `cargo test --workspace`
- CLI smoke test: `cargo run -p nousb -- doctor`
- CLI plan preview: `cargo run -p nousb -- plan boot-once ubuntu-24.04-desktop`
- Host one-shot preview: `cargo run -p nousb -- boot plan ubuntu-24.04-desktop`
- Feature lint: `cargo clippy -p nousb --all-targets --features real-linux-boot -- -D warnings` (or `real-windows-boot` on Windows)

## Standards

- Keep platform-specific code isolated in the platform crates.
- Planner code must produce a preview before any executor code can run.
- Critical actions require typed confirmation and cannot be bypassed with a simple yes flag.
- Do not use `unwrap` or `expect` in production paths.
- Prefer typed models over stringly-typed boot or disk operations.
- Default features must remain safe and non-destructive.

