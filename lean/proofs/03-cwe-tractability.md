# CWE Tractability — Expanded table

This document expands the tier taxonomy from `LEAN_PROOFS.md` with
per-CWE notes and references.

## Tier 1 — Type-shaped, proof-tractable, simple types suffice

These admit `Unsafe[T]` / `Tainted[T]` style proofs in vanilla STLC +
parametric polymorphism.

| CWE | Name | Source | Sink | Key prior art |
|-----|------|--------|------|---------------|
| 502 | Deserialization | `pickle.loads` | any concrete-typed use | this project |
| 94 | Code Injection | `eval`, `exec`, `compile` | invocation | same shape as 502 |
| 78 | OS Command Injection | untrusted `str` | `subprocess(..., shell=True)` | tainted-string literature |
| 89 | SQL Injection | untrusted `str` | raw SQL concat | parameterized-query types |
| 79 | XSS | untrusted `str` | HTML render context | LIO, JSure |
| 1336 | SSTI | untrusted `str` | template render | same shape as XSS |
| 611 | XXE | parser config | XML parse | parser-config type |
| 918 | SSRF | untrusted `str`/`URL` | HTTP client | URL-class typing |
| 601 | Open Redirect | untrusted `str` | redirect handler | subset of 918 |
| 295 | Improper Cert Validation | cert-validation flag | TLS handshake | `VerifiedTLS[Conn]` |
| 117 | Log Injection | untrusted `str` | `logger.*` | output-context typing |

## Tier 2 — Type-shaped, but needs heavyweight type extensions

| CWE | Name | Required extension | Key prior art |
|-----|------|-------------------|---------------|
| 200 | Information Exposure | IFC lattice | Jif, FlowCaml, LIO, MAC |
| 209 | Info via Error Messages | IFC | LIO |
| 862/863 | Missing/Incorrect Authz | Capability types, ghost principals | Granule, F* |
| 285 | Improper Authorization | Capability + ghost | F* / Idris |
| 352 | CSRF | Session types, origin-token state | Session types literature |
| 384 | Session Fixation | Session types | Session types |
| 915 | Mass Assignment | Row-polymorphic / sealed records | OCaml objects, Scala |
| 732 | Incorrect Permissions | Capability + filesystem types | F* file-system models |
| 22 | Path Traversal | Refinement on paths | Liquid Haskell |
| 798 | Hardcoded Credentials | `Secret[str]` + IFC | LIO |

## Tier 3 — Quantitative or value-level — types help, can't prove alone

| CWE | Name | Why types fail alone |
|-----|------|---------------------|
| 327 | Broken Crypto | Can't prove "AES-GCM correctly applied" |
| 326 | Inadequate Encryption Strength | Key-size is value-level |
| 330 | Insufficient Entropy | Entropy is statistical |
| 331 | Insufficient Entropy in PRNG | Same |
| 916 | Use of Password Hash w/ Insufficient Effort | Cost parameter is value-level |

## Tier 4 — Refinement types only (Liquid / F* / dependent)

| CWE | Name | Required reasoning |
|-----|------|-------------------|
| 787 | Out-of-bounds Write | Index ≤ length |
| 125 | Out-of-bounds Read | Same |
| 190 | Integer Overflow | Bounded-int types |
| 191 | Integer Underflow | Same |
| 369 | Divide by Zero | Non-zero refinement |
| 770 | Resource Allocation w/o Limits | Cost types, sized types |
| 400 | Uncontrolled Resource Consumption | Same |

## Tier 5 — Concurrency / temporal — needs different logic

| CWE | Name | Required logic |
|-----|------|----------------|
| 362 | Race Condition / TOCTOU | Concurrent separation logic |
| 367 | TOCTOU | Same |
| 401 | Memory Leak | Linear/affine types |
| 416 | Use-After-Free | Ownership types |
| 415 | Double Free | Linear types |

## Tier 6 — Out of scope by definition

| CWE | Name | Reason |
|-----|------|--------|
| 840 | Business Logic Errors | Application-semantic; no type captures "developer intent" |
| 693 | Protection Mechanism Failure | Umbrella category; requires specification of the mechanism |

## Generalization

The Lean proof for CWE-502 generalizes to a **Tier-1 lemma library** by
parameterizing:
- `Source : Set Expr` — untrusted primitives
- `Sink : Set Expr` — dangerous consumers
- `Tainted : Ty → Ty` — taint marker type

Pickle is simply the first instance where `Source = {loads}` and
`Sink = {concrete-typed use}`.

## CWE-502 extension plan

The same proof family should split into two layers:

1. **Returned-value quarantine** (current model): deserialization results are
   `Unsafe` and cannot reach concrete sinks without `cast`.
2. **Trusted-input preconditions** (next): calls to dangerous loaders require
   a precondition on provenance (`TrustedBytes`/`TrustedPath`), and may still
   return `Unsafe`.

The second layer is where current CVEs in the backlog are captured: many advisories
execute during `load(s)` before any meaningful return value exists, so proof
obligations there are about caller-side trust and admissible load sources, not
about automatic sanitization from the return type.
