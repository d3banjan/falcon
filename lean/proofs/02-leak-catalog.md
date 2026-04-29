# Leak catalog — why each strict-profile flag exists

Each disabled feature in the soundness-oriented type profile corresponds
to a formal leak documented in `Leaks.lean`.

| Flag / Rule | Formal leak | Lean file | Notes |
|-------------|-------------|-----------|-------|
| `disallow_any_explicit` | Any-absorption | `Leaks.lean` §AnyAbsorption | `any` absorbs taint silently |
| `disallow_any_expr` | Any-absorption | `Leaks.lean` §AnyAbsorption | expressions inferred as `Any` |
| ruff S307 (ban getattr) | getattr | `Leaks.lean` §GetattrLeak | runtime lookup bypasses typing |
| — | monkey-patch | `Leaks.lean` §MonkeyPatch | out of scope; requires linear types |
| `warn_unused_ignores` | kwargs Any | `Leaks.lean` §KwargsAny | `**kwargs` untyped forwarding |

## Any-absorption

When `Any` is permitted, it acts as a universal sink and source. A value
of type `Unsafe[bytes]` can be assigned to `Any`, and then `Any` can be
assigned to `Trusted[str]`. The type system sees no error, but taint has
flowed across the boundary.

**Mitigation**: ban `Any` entirely in security-critical code paths.

## getattr

`getattr(mod, name)` has type `Any` regardless of what attribute is being
looked up. If `mod` is `pickle` and `name` is `"loads"`, the result is the
dangerous function but typed as harmless `Any`. An immediate call on the
result is invisible to the type system.

**Mitigation**: static ban on `getattr` for modules that export `Unsafe`
primitives.

## Monkey-patch

Python modules are mutable. `pickle.loads = my_safe_loader` changes the
runtime behavior of every call to `pickle.loads`, but the stub still
claims it returns `Unsafe[Any]`. This does not create a vulnerability,
but it makes the type system unsound in the "too pessimistic" direction.

**Mitigation**: out of scope for a type system. Requires runtime
sandboxing or module sealing.

## kwargs Any

`def f(**kwargs): ...` creates a dictionary of type `dict[str, Any]`.
If `kwargs` is forwarded to a sink, the type system loses track of which
keys are tainted. `Unpack[TypedDict]` restores precision.

**Mitigation**: require `TypedDict` for all `**kwargs` in security-critical
functions.
