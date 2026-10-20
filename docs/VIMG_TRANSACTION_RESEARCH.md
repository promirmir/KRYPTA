# KRYPTA VIMG/0 — transaction research checkpoint

The experimental image now supports multi-sector `write_many()` commits and byte-range `write_at()` / `read_at()` access. No physical device is ever opened.

Each transaction writes encrypted sector versions first, then publishes one authenticated manifest. A read/write failure after disk I/O begins poisons the current handle; the caller must close and reopen the file before deciding whether the commit was durable.

Each manifest has a cryptographic `commit_receipt`. A caller can provide `expected_receipt` on reopen to detect replacement with a different committed state. **KRYPTA does not yet provide an independently protected receipt store.** Saving the receipt next to a stolen image cannot prevent rollback.

The implementation has not proven crash atomicity on actual storage hardware. It has no trusted monotonic counter, secure PIN unlock, transaction compaction, mountable virtual device, preboot encryption or production key recovery.

Tests: `tests/test_volume_transactions.py` and `tests/test_volume_transaction_model.py` include overlapping byte writes, frame/commit interruptions, tamper-rejection and ambiguous-acknowledgement scenarios. These test a software model, not real power-loss behavior.

Primary requirements: [PROJECT_CHARTER](PROJECT_CHARTER.md). Design: [VOLUME_IMAGE_V0](VOLUME_IMAGE_V0.md).
