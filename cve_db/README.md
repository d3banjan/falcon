# CVE Database

Machine-readable evidence records for CVE-driven stub coverage.

Start with:

- `libraries/pickle.jsonl` — seed records for Python pickle-backed deserialization CVEs.
- `reports/pickle-2026-04-30.md` — first run against the implemented falcon pickle/shelve stubs.
- `reports/downstream-stubs-2026-04-30.md` — surgical third-party wrapper stub coverage.
- `../docs/cve-database.md` — workflow, schema, catchability categories, and validation policy.

Records are JSON Lines: one CVE-library finding per line.

## Candidate Collection

Use the public OSV PyPI dump to generate broad candidates:

```bash
uv run python cve_db/tools/collect_candidates.py --osv
```

Generated files are written to `cve_db/generated/`, which is ignored. Promote only human-triaged records into `cve_db/libraries/*.jsonl`.
