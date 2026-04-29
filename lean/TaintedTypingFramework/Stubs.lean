import TaintedTypingFramework.Syntax

/-!
# Stubs.lean — Unsafe[T], cast, and pickle.loads primitives

This module collects the trusted primitives that form the stub layer.
In real Python these correspond to:
- `pickle.loads : bytes -> Any`  →  here typed as `bytes → Unsafe[Any]`
- `typing.cast[T, U](x) : T`    →  here typed as `Unsafe[σ] → τ`

Both are identity at runtime; only the type system sees the difference.
-/

namespace TaintedTypingFramework

/-- `pickle.loads` as a typed primitive.
    It is treated as a source of tainted data. -/
def pickleLoads (e : Expr) : Expr := Expr.loads e

/-- `typing.cast` as a typed primitive.
    It is the trusted escape hatch. -/
def typingCast (τ : Ty) (e : Expr) : Expr := Expr.cast τ e

end TaintedTypingFramework
