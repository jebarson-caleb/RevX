# Contributing to NoUSB OS Switcher

Thanks for helping. This tool changes how computers boot, so every change follows the safety rules below.

## Ground rules

- Default builds must stay non-destructive. Real boot changes live only behind `real-windows-boot`, `real-linux-boot`, or the desktop `real-boot` feature.
- Planner code produces a preview before any executor runs. High-risk and critical actions need an exact typed phrase; `--yes` never bypasses it.
- Never overwrite an existing boot file, and never change the default boot entry or persistent boot order.
- No `unwrap` or `expect` in production paths. No hidden telemetry.
- Keep platform code in the platform crates, and test it with `ScriptedCommandRunner` or fake adapters so no real `bcdedit` or `efibootmgr` runs in tests.

More detail: [AGENTS.md](AGENTS.md), [docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p nousb --all-targets --features real-linux-boot -- -D warnings     # on Linux
cargo clippy -p nousb --all-targets --features real-windows-boot -- -D warnings   # on Windows
cargo test --workspace
```

For the desktop app: `cd apps/desktop && pnpm install --frozen-lockfile && pnpm run build`.

## Changing installer profiles

Profiles live in `crates/nousb-installer-profiles/profiles/*.toml`. A new or changed profile needs the official HTTPS URL, the exact byte size, the SHA-256 from the vendor's signed checksum file, and a pinned signing key. Pinned hashes and URLs are data that users trust, so call them out in the pull request and in `CHANGELOG.md`.

## Physical testing

Reports from real hardware are especially valuable. Follow [docs/PHYSICAL_TESTING.md](docs/PHYSICAL_TESTING.md) and use the "Physical test report" issue template.

## Licensing

By contributing, you agree that your contributions are dual-licensed under Apache-2.0 and MIT, as described in the README, without additional terms.
