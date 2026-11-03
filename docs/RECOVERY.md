# Recovery

Recovery packs are written to `recovery-packs/pack-<timestamp>`.

The current pack includes:

- Host OS and architecture.
- Firmware and Secure Boot state as detected by the safe adapter.
- Encryption status placeholder.
- Manual recovery instructions.

This is not a full user-data backup. Replace-current-OS flows must require acknowledgement that a verified external user-data backup exists before real adapters are enabled.

## Resuming or Rolling Back a Saved Operation

Every simulated execution is saved under `.nousb/reports/<plan-id>.json`. Three commands consume those reports:

```sh
cargo run -p nousb -- reports recover <plan-id>   # assessment only
cargo run -p nousb -- resume <plan-id>            # continue a cleanly interrupted operation
cargo run -p nousb -- rollback <plan-id>          # undo a failed or interrupted operation
```

`reports recover` recommends one action:

| Saved state | Recommendation | Why |
| --- | --- | --- |
| Any step needs manual intervention | `manual_intervention` | Nothing runs until a human clears the hold; use the recovery pack. |
| Any step failed | `rollback` | A failed step is never retried automatically. |
| Already rolled back, or every step completed | `nothing_to_do` | Repeating either would not be idempotent. |
| Interrupted with pending or running steps | `resume` | Completed steps are kept. A step that was running at interruption is re-run from its start, so real adapters must make every step idempotent before resume is enabled for them. |

`resume` refuses anything that is not recommended for resume. `rollback` refuses completed, already-rolled-back, and manual-hold operations. Both write an updated report and a journal entry. Saved reports come only from simulations today, because `execute` is blocked in the default build. These commands therefore never read or change host boot state.

## Diagnostics

Use:

```sh
cargo run -p nousb -- diagnostics export
```

Diagnostic bundles are written to `.nousb/diagnostics/bundle-<timestamp>`. They are not recovery packs, but they help inspect local operation state. Secret-like log lines are redacted before export.
