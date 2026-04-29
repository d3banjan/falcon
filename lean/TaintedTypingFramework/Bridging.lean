/-!
# Bridging.lean — Gap analysis to real mypy / CPython

This is an **informal** markdown chapter (rendered as Lean comments)
documenting why the formal proof does not transfer to real Python.

## 1. mypy's gradual typing: `Any` is implicit, not opt-in

In the model, `Unsafe[τ]` is explicit. In mypy, `Any` propagates
implicitly through un-annotated code. A function missing a return
annotation is inferred as returning `Any`, silently absorbing taint.

## 2. mypy plugin instability

The model assumes the only mechanism for changing type semantics is
`cast`. Real mypy has plugins (e.g. for `numpy`, `SQLAlchemy`) that
can introduce arbitrary typing rules. We do not model plugin behavior.

## 3. CPython runtime escapes

- `__class__` reassignment
- `__instancecheck__` override
- Descriptor magic (`__get__`, `__set__`)
- `sys.modules` mutation

None of these are in the Tier-1 fragment, and each provides a way to
break type abstraction at runtime.

## 4. C extension calls

The stub `_pickle.pyi` claims `loads : bytes -> Any`. The actual
`_pickle.so` might have different behavior (e.g. additional arguments,
platform-specific defaults). We trust typeshed authors as part of the TCB.

## 5. Stub authors are in the TCB

A wrong stub breaks soundness silently. If `_pickle.pyi` were changed
to `loads : bytes -> SafeAny`, the type system would believe pickle is
safe even though the runtime is not.

## Honest summary

The Lean proof is a proof about a **hypothetical sound subset** of Python.
It shows *what would be true* if Python had:
- no implicit `Any`
- no runtime introspection (`getattr`, `eval`, monkey-patching)
- no plugin-extensible type system
- perfect stub fidelity

Real Python satisfies none of these. The proof is still valuable:
it gives a formal target for linter rules (ruff, mypy strict flags)
and documents exactly which language features must be removed to make
type-driven security proof possible.
-/

namespace TaintedTypingFramework

-- This module contains no Lean definitions; it is documentation only.

end TaintedTypingFramework
