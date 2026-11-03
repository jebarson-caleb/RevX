# Contributing

The full guide is in the repository root: [CONTRIBUTING.md](../CONTRIBUTING.md).

Keep changes small, typed, and testable.

Before submitting:

```sh
cargo fmt --all
cargo test --workspace
```

Rules:

- No production `unwrap` or `expect`.
- No hidden telemetry.
- No real boot changes in default features.
- Use platform APIs or tightly wrapped commands.
- Add tests for planner, risk, confirmation, catalog, journal, and adapter parsing changes.

