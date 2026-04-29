import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Semantics
import TaintedTypingFramework.Types
import TaintedTypingFramework.Vulnerable
import TaintedTypingFramework.Soundness

/-!
# Leaks.lean — Counter-examples

Each counter-example demonstrates a soundness break when the Tier-1
fragment is extended with a single feature.

1. **Any-absorption** — `any` type that absorbs everything.
2. **getattr** — runtime name lookup bypasses the type system.
3. **Monkey-patch** — mutable module state invalidates typing.
4. **Implicit Any from kwargs** — untyped forwarding loses taint.
-/

namespace TaintedTypingFramework

section AnyAbsorption

/-- Extend `Ty` with an `any` type that subsumes all types. -/
inductive TyExt : Type
  | any : TyExt
  | base : Ty → TyExt

/-- Extend typing with `any` absorption. -/
inductive TypedAny : TypeEnv → Expr → TyExt → Prop
  | T_any : ∀ Γ e, TypedAny Γ e TyExt.any

/-- Counter-example: with `any` absorption, a tainted value can be
    typed at any concrete type without `cast`. -/
theorem any_breaks_soundness :
    ∃ (Γ : TypeEnv) (e : Expr) (τ : TyExt) (v : Value),
    TypedAny Γ e (TyExt.base (Ty.concrete "Foo")) ∧
    Eval e v ∧
    Vulnerable v := by
  sorry

end AnyAbsorption

section GetattrLeak

/-- Extend `Expr` with `getattr`. -/
inductive ExprGetattr : Type
  | base : Expr → ExprGetattr
  | getattr : ExprGetattr → String → ExprGetattr

/-- `getattr pickle "loads"` evaluates like `loads` but is typed `Any`. -/
theorem getattr_breaks_soundness :
    ∃ (e : Expr) (v : Value),
    Eval (Expr.loads (Expr.const (Value.vbytes "x"))) v ∧
    Vulnerable v := by
  sorry

end GetattrLeak

section MonkeyPatch

/-- Mutable module state makes `loads` return untainted bytes. -/
theorem monkey_patch_breaks_soundness :
    ∃ b v,
    Eval (Expr.loads (Expr.const (Value.vbytes b))) v ∧
    ¬ isTainted v := by
  sorry

end MonkeyPatch

section KwargsAny

/-- Untyped `**kwargs` forwarding loses taint tracking. -/
theorem kwargs_any_breaks_soundness :
    ∃ Γ e τ v,
    Typed Γ e τ ∧
    isConcrete τ ∧
    Eval e v ∧
    Vulnerable v := by
  sorry

end KwargsAny

end TaintedTypingFramework
