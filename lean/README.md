# TaintedTypingFramework

Type-driven security proofs for a sound subset of Python.

## Scope

This is a **model**, not a proof that real mypy or CPython is sound.
See `TaintedTypingFramework/Bridging.lean` for the honest gap analysis.

## Structure

- `TaintedTypingFramework/Syntax.lean` — expression AST for a tiny Python fragment
- `TaintedTypingFramework/Semantics.lean` — big-step operational semantics
- `TaintedTypingFramework/Types.lean` — type rules Γ ⊢ e : τ
- `TaintedTypingFramework/Stubs.lean` — `Unsafe[T]`, `cast`, `pickle.loads` primitives
- `TaintedTypingFramework/Vulnerable.lean` — vulnerability predicate V(v)
- `TaintedTypingFramework/Soundness.lean` — Theorem 1 (pickle soundness) + Theorem 2 (cast = only escape)
- `TaintedTypingFramework/Leaks.lean` — counter-examples: Any, getattr, monkey-patch, kwargs
- `TaintedTypingFramework/Bridging.lean` — gap analysis → real mypy (informal)
- `proofs/` — prose walkthroughs of each theorem

## Build

```bash
lake build
```
