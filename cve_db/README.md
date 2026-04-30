# CVE Database

Machine-readable evidence records for CVE-driven stub coverage.

Start with:

- `libraries/pickle.jsonl` — seed records for Python pickle-backed deserialization CVEs.
- `reports/pickle-2026-04-30.md` — first run against the implemented falcon pickle/shelve stubs.
- `reports/downstream-stubs-2026-04-30.md` — surgical third-party wrapper stub coverage.
- `../docs/cve-database.md` — workflow, schema, catchability categories, and validation policy.

Records are JSON Lines: one CVE-library finding per line.
