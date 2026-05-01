# OSV Candidate Triage Buckets — 2026-05-01

Source file: `falcon/cve_db/generated/deserialization-candidates.jsonl`
Input size: **221** rows.

## Method (first-pass, machine-readable by construction)

For each JSONL row, I applied an ordered heuristic:

1. **Duplicate**: summary/details contains `duplicate advisory`.
2. **Out-of-scope**:
   - analyzer-policy advisories for `picklescan` or `fickling`, or
   - withdrawn advisory language, or
   - records whose primary weakness is scanner classification rather than application source-to-sink flow.
3. **Malicious-package**:
   - record ID is `MAL-*`, or
   - explicit malicious package/code wording.
4. **False-positive**: clearly non-type-coverage issues (`crlf`, `key confusion`, OOB/libwebp, etc.).
5. **Needs-source-confirmation**: disputed/ambiguous language (`** disputed **`, explicit third-party dispute, unclear attacker control assumptions, etc.).
6. **Catchable**: explicit sink call family + exploit text (e.g. `pickle.load`, `yaml.load`, `marshal.load`, `joblib.load`, `dill`, `jsonpickle`, etc. plus remote/ arbitrary code execution indicators).
7. **Partial**: remaining rows with deserialization-relevant term matches not meeting strict catchable criteria.

This is intentionally conservative and meant to produce a curated denominator for later manual review, not a final verdict.

## Bucket counts

| Bucket | Count |
|---|---:|
| catchable | 31 |
| partial | 37 |
| out-of-scope | 73 |
| duplicate | 10 |
| malicious-package | 14 |
| false-positive | 7 |
| needs-source-confirmation | 49 |
| **Total** | **221** |

## Representative examples by bucket

| Bucket | Example rows (non-exhaustive) |
|---|---|
| catchable | `GHSA-hpj3-5p46-g87w`, `GHSA-r38r-qp28-2m63`, `GHSA-87r7-q54j-f9qg`, `GHSA-m85c-9mf8-m2m6`, `GHSA-fm6c-f59h-7mmg` |
| partial | `GHSA-hf26-vvmx-x8c8`, `GHSA-pvhp-v9qp-xf5r`, `GHSA-qgvw-qc2q-gv5q`, `GHSA-v7mh-3jgf-r26c`, `GHSA-m923-w2gj-v43g` |
| out-of-scope | `GHSA-jgw4-cr84-mqxg`, `GHSA-mjqp-26hc-grxg`, `GHSA-f7qq-56ww-84cr`, `GHSA-655q-fx9r-782v`, `GHSA-7q5r-7gvp-wc82` |
| duplicate | `GHSA-2fh4-gpch-vqv4`, `GHSA-4p4h-9gvq-7xfg`, `GHSA-4vr7-g93g-cf6m`, `GHSA-77wq-646f-jrm2`, `GHSA-8x2r-v9x5-3qgh` |
| malicious-package | `GHSA-mcrp-whpw-jp68`, `MAL-2024-10028`, `MAL-2024-10041`, `MAL-2024-10048`, `MAL-2024-10184` |
| false-positive | `GHSA-r9jw-mwhq-wp62`, `GHSA-32pc-xphx-q4f6`, `GHSA-m982-h4f8-g4hf`, `GHSA-fj5v-w2jp-wqvj`, `GHSA-ffqj-6fqr-9h24` |
| needs-source-confirmation | `GHSA-wcpc-f63g-x26q`, `GHSA-vxp9-wv2f-wqmw`, `GHSA-22mf-97vh-x8rw`, `GHSA-9fq2-x9r6-wfmf`, `PYSEC-2020-73` |


## Caveats

- This is a first-pass triage view over broad keyword matches only; source-to-sink evidence is not verified for every row.
- `malicious-package`, `duplicate`, and `out-of-scope` are explicitly separated so they are not mixed into the Falcon catchability denominator.
- The `catchable` vs `partial` split is intentionally high-level and should be re-validated per package/API before producing final coverage numbers.
- No source files, JSONL inputs, stubs, tests, or docs were edited; this is a reporting artifact only.

```json
{
  "date": "2026-05-01",
  "input": "falcon/cve_db/generated/deserialization-candidates.jsonl",
  "total_rows": 221,
  "buckets": {
    "catchable": 31,
    "partial": 37,
    "out_of_scope": 73,
    "duplicate": 10,
    "malicious_package": 14,
    "false_positive": 7,
    "needs_source_confirmation": 49
  }
}
```
