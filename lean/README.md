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
  - **Proved**: `soundness` (from the lemmas above)
  - **Stubbed**: `eval_closure_noloads_body` (needs `Eval` induction)
  - **Stubbed**: `typed_concrete_no_loads` (needs substitution lemma for `Typed`)
  - **Stubbed**: `cast_only_escape` (needs side-lemma about function types)
- `TaintedTypingFramework/Leaks.lean` — counter-examples
  - **Proved**: `any_breaks_soundness` (Any-absorption)
  - **Proved**: `monkey_patch_breaks_soundness` (mutable module state)
  - **Proved**: `getattr_breaks_soundness`
  - **Proved**: `kwargs_any_breaks_soundness`
- `TaintedTypingFramework/Bridging.lean` — gap analysis → real mypy (informal)
- `TaintedTypingFramework/TrustedInputs.lean` — trusted-input precondition model
- `proofs/` — prose walkthroughs of each theorem

## Current proof contract

The Lean model proves only **post-return quarantine**: values returned from
dangerous deserialisers are typed as `Unsafe[Any]`, and they cannot cross into
trusted concrete sinks without an explicit `cast`.

It does not currently prove that dangerous loaders are safe on attacker-provided
input.

- `loads` is modeled as a source of taint at the return point.
- The model intentionally does not represent the load-time effects (including
  arbitrary code execution) of `pickle.loads`/`cloudpickle.loads`/`torch.load`
  and unsafe loaders.
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
| Theorem 1 (soundness) | ✅ Proved | Depends on 2 stubbed lemmas |
| Theorem 2 (cast = only escape) | ⬜ Stubbed | `app_r` case needs function-type side-lemma |
| Any-absorption | ✅ Proved | `TyAny` + `TypedAny` |
| Monkey-patch | ✅ Proved | `EvalMonkey` |
| Getattr | ✅ Proved | Extended `ExprGetattr` model |
| Kwargs | ✅ Proved | Extended `ExprKwarg` model |
| Trusted loader preconditions | ✅ Proved | `TrustedInputs.lean` requires trusted inputs and still returns `Unsafe[Any]` |

## Lean backlog

- Extend the first trusted-input model beyond the current `TrustedBytes` /
  `TrustedPath` precondition theorem into a fuller ingress-provenance lattice
  for network, RPC, queue, and remote artifact sources.
- Add a theorem family for load-time risk classification:
  `load(s)` may execute before any typed return, so return-only proofs alone are
  not enough to cover the published CVE semantics.
- Finish existing Lean placeholders:
  `eval_closure_noloads_body`, `typed_concrete_no_loads`, and
  `cast_only_escape` in `Soundness.lean`.
