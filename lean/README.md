# TaintedTypingFramework

Type-driven security proofs for a sound subset of Python.

## Scope

This is a **model**, not a proof that real mypy or CPython is sound.
See `TaintedTypingFramework/Bridging.lean` for the honest gap analysis.

## Structure

- `TaintedTypingFramework/Syntax.lean` — expression AST for a tiny Python fragment
  - Mutual inductives: `Ty` (with `unsafe_` marker), `Value`, `Expr`
- `TaintedTypingFramework/Semantics.lean` — big-step operational semantics
  - Closed-term substitution semantics (`Eval e v`)
- `TaintedTypingFramework/Types.lean` — type rules Γ ⊢ e : τ
  - Simply-typed lambda calculus with `arrow` types
  - `loads : bytes → unsafe_ (concrete "Any")`
  - `cast : unsafe_ σ → τ` (trusted escape)
- `TaintedTypingFramework/Stubs.lean` — `Unsafe[T]`, `cast`, `pickle.loads` primitives
- `TaintedTypingFramework/Vulnerable.lean` — vulnerability predicate `V(v)`
- `TaintedTypingFramework/Soundness.lean` — Theorem 1 + Theorem 2
  - **Proved**: `subst_preserves_noloads`, `eval_not_tainted_without_loads`
  - **Conditional**: `soundness` still depends on placeholder lemmas
  - **Counterexample documented**: `eval_closure_noloads_body` is false for
    closure constants unless `NoLoads` is strengthened for values
  - **Counterexample documented**: `typed_concrete_no_loads` is false when a
    concrete-typed function ignores an unsafe argument
  - **Counterexample documented**: `cast_only_escape` is false for the same
    higher-order shape
- `TaintedTypingFramework/Leaks.lean` — counter-examples
  - **Proved**: `any_breaks_soundness` (Any-absorption)
  - **Proved**: `monkey_patch_breaks_soundness` (mutable module state)
  - **Proved**: `getattr_breaks_soundness`
  - **Proved**: `kwargs_any_breaks_soundness`
- `TaintedTypingFramework/Bridging.lean` — gap analysis → real mypy (informal)
- `TaintedTypingFramework/TrustedInputs.lean` — trusted-input precondition model
- `TaintedTypingFramework/ImportedLoaders.lean` — generic imported-loader specs
- `TaintedTypingFramework/Ingress.lean` — untrusted ingress provenance examples
- `TaintedTypingFramework/Provenance.lean` — TrustedBytes/TrustedPath/TrustedArtifact promotion boundary
- `TaintedTypingFramework/LoadTime.lean` — load-time risk classification model
- `TaintedTypingFramework/SoundFragment.lean` — replacement invariant excluding
  known higher-order counterexamples
- `proofs/` — prose walkthroughs of each theorem

## Current proof contract

The Lean model proves only **post-return quarantine**: values returned from
dangerous deserialisers are typed as `Unsafe[Any]`, and they cannot cross into
trusted concrete sinks without an explicit `cast`.

It does not currently prove that dangerous loaders are safe on attacker-provided
input.

- `loads` is modeled as a source of taint at the return point.
- `TrustedInputs.lean` models trusted call-site preconditions for dangerous
  loaders.
- `ImportedLoaders.lean` generalizes this to imported code paths via a
  `ImportedLoaderSpec` containing path, input kind, return type metadata, and
  load-time-risk metadata. Concrete package APIs are examples of this relation,
  not separate theorem families.
- `Ingress.lean` models network, RPC, queue, socket, and remote artifact inputs
  as untrusted provenance sources that cannot satisfy trusted loader
  preconditions directly.
- `Provenance.lean` models explicit promotion evidence that can construct
  trusted inputs from ingress values. Promotion permits the call but still leaves
  the dangerous-loader return typed as `Unsafe[Any]`.
- `LoadTime.lean` classifies loader families whose execution may happen before
  any returned value is quarantined.
- The practical claim is therefore that Falcon can keep returned values tainted,
  not that load-time execution is blocked.

## Build

```bash
lake build
```

Expected output: build succeeds with `sorry`-declaration warnings only.

## Proof status

| Theorem | Status | Notes |
|---------|--------|-------|
| Theorem 1 (soundness) | Conditional | Depends on placeholder lemmas; counterexamples show the current statements need stronger invariants |
| Theorem 2 (cast = only escape) | Blocked | Counterexample shows the statement is false for ignored unsafe arguments |
| Any-absorption | ✅ Proved | `TyAny` + `TypedAny` |
| Monkey-patch | ✅ Proved | `EvalMonkey` |
| Getattr | ✅ Proved | Extended `ExprGetattr` model |
| Kwargs | ✅ Proved | Extended `ExprKwarg` model |
| Trusted loader preconditions | ✅ Proved | `TrustedInputs.lean` requires trusted inputs and still returns `Unsafe[Any]` |
| Generic imported-loader specs | ✅ Proved | `ImportedLoaders.lean` models library paths as data, not new constructors |
| Ingress provenance rejection | ✅ Proved | `Ingress.lean` rejects direct network/RPC/queue/socket/artifact ingress at trusted loader calls |
| Trusted provenance promotion | ✅ Proved | `Provenance.lean` permits promoted inputs while preserving `Unsafe[Any]` returns |
| Load-time risk classification | ✅ Proved | `LoadTime.lean` separates call-time risk from returned-value quarantine |
| Replacement sound fragment | ✅ Proved | `SoundFragment.lean` rejects the counterexample shapes found in `Soundness.lean` |

## Lean backlog

- Add a backend-evidence model for the next Falcon architecture slice:
  `StubEvidence`, `ASTEvidence`, and `AppTypeEvidence` should all justify the
  same taint result without declassifying `Unsafe[Any]`.
- Add a conditional-config proof family for unsafe literal policy flags such as
  `allow_pickle=True`, `safe=False`, `remote_exec=True`, and
  `trust_remote_code=True`.
- Add a wrapper-forwarding proof family that turns wrapper evidence into an
  imported-loader spec when a wrapper forwards trusted input or unsafe config
  into a dangerous loader.
- Prefer `ImportedLoaders.lean` for future package/API coverage: imported code
  paths should be data in a generic spec, not new Lean constructors.
- Unify or retire the older enumerated `Loader` examples once the generic
  imported-loader model has enough documentation and regression coverage.
- Connect the provenance promotion model to more concrete validator APIs as
  those APIs stabilize.
- Finish existing Lean placeholders:
  `eval_closure_noloads_body`, `typed_concrete_no_loads`, and
  `cast_only_escape` in `Soundness.lean`. Current counterexamples show these
  statements need stronger invariants before the `sorry`s can honestly close.
