# CVE Database

Machine-readable evidence records for CVE-driven stub coverage.

Start with:

- `libraries/pickle.jsonl` — seed records for Python pickle-backed deserialization CVEs.
- `libraries/serialization-sinks.jsonl` — OSV-promoted rows for adjacent sinks such as YAML, dill, joblib, marshal, pandas pickle helpers, skops model-card loading, and torch-load model artifacts.
- `reports/pickle-2026-04-30.md` — first run against the implemented falcon pickle/shelve stubs.
- `reports/downstream-stubs-2026-04-30.md` — surgical third-party wrapper stub coverage.
- `reports/osv-deserialization-candidates-2026-05-01.md` — latest reproducible OSV candidate run and promoted sink-family rows.
- `reports/osv-triage-buckets-2026-05-01.md` — first-pass bucket triage over the 221 OSV candidates.
- `reports/deep-research-serialization-backlog-2026-05-01.md` — source-confirmed wrapper backlog, do-not-implement list, and Lean proof-model implications.
- `../docs/cve-database.md` — workflow, schema, catchability categories, and validation policy.

Records are JSON Lines: one CVE-library finding per line.

## Candidate Collection

Use the public OSV PyPI dump to generate broad candidates:

```bash
uv run python cve_db/tools/collect_candidates.py --osv
```

On 2026-05-01 the expanded keyword profile found 221 broad candidates. The first-pass triage buckets are: 31 catchable, 37 partial, 73 out-of-scope, 10 duplicate, 14 malicious-package, 7 false-positive, and 49 needs-source-confirmation. Generated files are written to `cve_db/generated/`, which is ignored. Promote only human-triaged records into `cve_db/libraries/*.jsonl`.
