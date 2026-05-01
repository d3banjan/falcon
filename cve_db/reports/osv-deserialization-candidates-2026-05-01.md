# OSV Deserialization Candidate Run: 2026-05-01

Command:

```bash
uv run python cve_db/tools/collect_candidates.py --osv
```

Result after expanding keywords beyond pickle:

| Metric | Count |
|---|---:|
| Broad OSV PyPI candidates | 221 |
| Prior broad candidates with pickle-focused profile | 182 |
| Human-promoted rows added in `libraries/serialization-sinks.jsonl` | 10 |

Top matched terms:

| Term | Count |
|---|---:|
| `pickle` | 171 |
| `pickle.load` | 87 |
| `pickle.loads` | 41 |
| `marshal` | 19 |
| `torch.load` | 18 |
| `yaml.load` | 15 |
| `unpickle` | 15 |
| `dill` | 9 |
| `cloudpickle` | 5 |
| `joblib` | 4 |
| `shelve` | 3 |
| `jsonpickle` | 2 |
| `allow_pickle` | 2 |

Immediate sink-family actions completed:

| Sink family | Stub status | Fixture status |
|---|---|---|
| `dill.load`, `dill.loads` | Added | Validated in checker fixture |
| `joblib.load` | Added | Validated in checker fixture |
| `marshal.load`, `marshal.loads` | Added | Validated in checker fixture |
| `yaml.load`, `yaml.unsafe_load`, `yaml.full_load` | Added | Validated in checker fixture |

Interpretation:

The 221 records are still not a Falcon coverage denominator. The feed contains duplicate GHSA/CVE aliases, malicious-package records, analyzer-bypass advisories, disputed records, denial-of-service-only records, and substring noise. Coverage claims should use curated JSONL rows only.

Next normalization pass:

1. Split analyzer-bypass records such as Picklescan/Fickling into `out-of-scope`.
2. Split malicious package records into a separate supply-chain bucket.
3. Promote package-wrapper rows for remaining scikit-learn joblib helpers, InvokeAI, vLLM torch loaders, Feast/PyYAML, and marshal-using packages where source locations are available.
4. Keep raw generated files ignored under `cve_db/generated/`.
