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
inductive TyAny : Type
  | any : TyAny
  | base : Ty → TyAny

/-- Extend typing with `any` absorption.
    `any` can be used at any type via `T_sub`. -/
inductive TypedAny : TypeEnv → Expr → TyAny → Prop
  | T_any    : ∀ Γ e, TypedAny Γ e TyAny.any
  | T_sub    : ∀ Γ e τ, TypedAny Γ e TyAny.any → TypedAny Γ e (TyAny.base τ)
  | T_const_unit  : ∀ Γ, TypedAny Γ (Expr.const Value.vunit) (TyAny.base Ty.unit)
  | T_const_bytes : ∀ Γ s, TypedAny Γ (Expr.const (Value.vbytes s)) (TyAny.base Ty.bytes)
  | T_const_int   : ∀ Γ n, TypedAny Γ (Expr.const (Value.vint n)) (TyAny.base Ty.int)
  | T_var    : ∀ Γ x τ, List.lookup x Γ = some τ → TypedAny Γ (Expr.var x) (TyAny.base τ)
  | T_lam    : ∀ Γ x τ τ' body,
      TypedAny ((x, τ) :: Γ) body (TyAny.base τ') →
      TypedAny Γ (Expr.lam x τ body) (TyAny.base (Ty.arrow τ τ'))
  | T_app    : ∀ Γ f arg τ τ',
      TypedAny Γ f (TyAny.base (Ty.arrow τ τ')) →
      TypedAny Γ arg (TyAny.base τ) →
      TypedAny Γ (Expr.app f arg) (TyAny.base τ')
  | T_loads  : ∀ Γ b,
      TypedAny Γ b (TyAny.base Ty.bytes) →
      TypedAny Γ (Expr.loads b) (TyAny.base (Ty.unsafe_ (Ty.concrete "Any")))
  | T_cast   : ∀ Γ e τ σ,
      TypedAny Γ e (TyAny.base (Ty.unsafe_ σ)) →
      TypedAny Γ (Expr.cast τ e) (TyAny.base τ)

/-- Counter-example: with `any` absorption, `loads` can be typed at any
    concrete type without `cast`, and it evaluates to a tainted value.
    This breaks Theorem 1. -/
theorem any_breaks_soundness :
    ∃ (Γ : TypeEnv) (e : Expr) (τ : Ty) (v : Value),
    TypedAny Γ e (TyAny.base (Ty.concrete "Foo")) ∧
    Eval e v ∧
    Vulnerable v := by
  exists []
  exists Expr.loads (Expr.const (Value.vbytes "x"))
  exists Ty.concrete "Foo"
  exists Value.tainted (Value.vbytes "x")
  apply And.intro
  · exact TypedAny.T_sub [] (Expr.loads (Expr.const (Value.vbytes "x"))) (Ty.concrete "Foo") (TypedAny.T_any [] (Expr.loads (Expr.const (Value.vbytes "x"))))
  apply And.intro
  · exact Eval.E_loads (Expr.const (Value.vbytes "x")) (Value.vbytes "x") (Eval.E_const (Value.vbytes "x"))
  · exact ⟨Value.vbytes "x", rfl⟩

end AnyAbsorption

section GetattrLeak

/-- Extend `Expr` with `getattr`. -/
inductive ExprGetattr : Type
  | base    : Expr → ExprGetattr
  | getattr : ExprGetattr → String → ExprGetattr

/-- Extended evaluation: `getattr (const pickle) "loads"` evaluates to
    the `loads` primitive. -/
inductive EvalGetattr : ExprGetattr → Value → Prop
  | E_base    : ∀ e v, Eval e v → EvalGetattr (ExprGetattr.base e) v
  | E_getattr : ∀ e v, EvalGetattr e (Value.vconcrete "module" v) →
      EvalGetattr (ExprGetattr.getattr e "loads") (Value.vclosure [] "b" Ty.bytes (Expr.loads (Expr.var "b")))

/-- Extended typing: `getattr` is typed as `any`, so it bypasses the
    `Unsafe` marker on `loads`. -/
inductive TypedGetattr : TypeEnv → ExprGetattr → Ty → Prop
  | T_base    : ∀ Γ e τ, Typed Γ e τ → TypedGetattr Γ (ExprGetattr.base e) τ
  | T_getattr : ∀ Γ e, TypedGetattr Γ e (Ty.concrete "Any") →
      TypedGetattr Γ (ExprGetattr.getattr e "loads") (Ty.arrow Ty.bytes (Ty.concrete "Any"))

/-- Counter-example: `getattr pickle "loads"` evaluates to the `loads`
    function but is typed as `bytes → Any` (not `bytes → Unsafe[Any]`).
    When applied to untrusted bytes, the result is tainted but typed as
    `Any`, which can then be implicitly used at concrete type in a system
    with `any` absorption. -/
theorem getattr_breaks_soundness :
    ∃ (e : ExprGetattr) (τ : Ty) (v : Value),
    TypedGetattr [] e τ ∧
    isConcrete τ ∧
    EvalGetattr e v ∧
    Vulnerable v := by
  sorry

end GetattrLeak

section MonkeyPatch

/-- Extended semantics with mutable module state.
    After monkey-patching, `loads b` returns `b` verbatim (untainted). -/
inductive EvalMonkey : Expr → Value → Prop
  | E_const   : ∀ v, EvalMonkey (Expr.const v) v
  | E_lam     : ∀ x τ body, EvalMonkey (Expr.lam x τ body) (Value.vclosure [] x τ body)
  | E_app     : ∀ f x body arg varg vbody τ,
      EvalMonkey f (Value.vclosure [] x τ body) →
      EvalMonkey arg varg →
      EvalMonkey (body.subst x (Expr.const varg)) vbody →
      EvalMonkey (Expr.app f arg) vbody
  | E_loads   : ∀ b vb, EvalMonkey b vb → EvalMonkey (Expr.loads b) vb
  | E_cast    : ∀ τ e v, EvalMonkey e v → EvalMonkey (Expr.cast τ e) v

/-- Counter-example: under monkey-patch semantics, `loads` returns the
    input bytes verbatim (not tainted). This breaks the type system's
    claim that `loads` returns `Unsafe[Any]` — the type system is now
    too pessimistic. This is a soundness break in the reverse direction. -/
theorem monkey_patch_breaks_soundness :
    ∃ (b : String) (v : Value),
    EvalMonkey (Expr.loads (Expr.const (Value.vbytes b))) v ∧
    ¬ isTainted v := by
  exists "x"
  exists Value.vbytes "x"
  apply And.intro
  · exact EvalMonkey.E_loads (Expr.const (Value.vbytes "x")) (Value.vbytes "x") (EvalMonkey.E_const (Value.vbytes "x"))
  · intro h
    cases h
    rename_i w hw
    cases hw

end MonkeyPatch

section KwargsAny

/-- Extend `Expr` with untyped `**kwargs` forwarding.
    `kwarg x` reads key `x` from the kwargs dict (typed `Any`). -/
inductive ExprKwarg : Type
  | base  : Expr → ExprKwarg
  | kwarg : ExprKwarg → String → ExprKwarg

/-- Extended typing: kwargs are untyped (`Any`). -/
inductive TypedKwarg : TypeEnv → ExprKwarg → Ty → Prop
  | T_base  : ∀ Γ e τ, Typed Γ e τ → TypedKwarg Γ (ExprKwarg.base e) τ
  | T_kwarg : ∀ Γ e x, TypedKwarg Γ e (Ty.concrete "Dict") →
      TypedKwarg Γ (ExprKwarg.kwarg e x) (Ty.concrete "Any")

/-- Counter-example: kwargs forwarding loses taint tracking.
    A function that receives tainted bytes via `**kwargs` and returns them
    is typed at `Any`, but in a system with `any` absorption this becomes
    usable at concrete type without cast. -/
theorem kwargs_any_breaks_soundness :
    ∃ (Γ : TypeEnv) (e : ExprKwarg) (τ : Ty) (v : Value),
    TypedKwarg Γ e τ ∧
    isConcrete τ ∧
    Vulnerable v := by
  sorry

end KwargsAny

end TaintedTypingFramework
