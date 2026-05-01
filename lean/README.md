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
- `TaintedTypingFramework/LoadTime.lean` — load-time risk classification model
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
| Load-time risk classification | ✅ Proved | `LoadTime.lean` separates call-time risk from returned-value quarantine |

## Lean backlog

- Extend the trusted-input model into a fuller ingress-provenance lattice for
  network, RPC, queue, socket, and remote artifact sources.
- Connect load-time risk classification to provenance so untrusted ingress is
  rejected before dangerous loader execution, not only quarantined afterward.
- Finish existing Lean placeholders:
  `eval_closure_noloads_body`, `typed_concrete_no_loads`, and
  `cast_only_escape` in `Soundness.lean`. Current counterexamples show these
  statements need stronger invariants before the `sorry`s can honestly close.
