## What and why

## Safety checklist

- [ ] Default builds stay non-destructive; any real boot change is behind `real-*-boot` and a typed phrase.
- [ ] No existing boot file, default entry, or persistent boot order can be overwritten.
- [ ] Platform commands are tested with `ScriptedCommandRunner` or fakes; no test runs `bcdedit`, `efibootmgr`, or `mountvol`.
- [ ] No `unwrap`/`expect` in production paths.
- [ ] Pinned URLs, sizes, or hashes changed? Noted in `CHANGELOG.md`.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
