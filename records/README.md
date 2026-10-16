# Records

One dated file per test or measurement, plus an index in [TEST_LOG.md](TEST_LOG.md).

**Evidence types**

| Type | Meaning |
|---|---|
| `LIVE` | over the air, with the real sensor |
| `SOFTWARE` | synthetic frames fed to the engine, no radio |
| `MEASUREMENT` | resource sampling (CPU, memory) |

**Add a record**

1. Copy [TEMPLATE.md](TEMPLATE.md) to `YYYY-MM-DD_<what>.md` and fill it in.
2. Add a row to [TEST_LOG.md](TEST_LOG.md).
3. Mask MACs with `python3 tools/mask_macs.py` ([docs/PRIVACY.md](../docs/PRIVACY.md)). Unmasked originals go in `records/raw/`, which is git-ignored.

Lines marked **TODO** are facts the author has not recorded yet. They are listed rather than guessed.
