import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Semantics
import TaintedTypingFramework.Types
import TaintedTypingFramework.Vulnerable

/-!
# Soundness.lean — Main theorems

Theorem 1 (Pickle soundness for sound fragment):
  If `e` is typed at a concrete type (not `Unsafe[_]`) and contains
  no `cast` subterm, then evaluation cannot produce a `Vulnerable` value.

Theorem 2 (cast is the only sound escape):
  If a well-typed expression at concrete type contains `loads b` as a
  subterm, then it must also contain a `cast τ (loads b)` somewhere.
-/

namespace TaintedTypingFramework

/-- A type is concrete if it is not `unsafe_ _`. -/
def isConcrete (τ : Ty) : Prop :=
  ∀ σ, τ ≠ Ty.unsafe_ σ

/-- A term contains no `cast` sub-expressions. -/
inductive NoCast : Expr → Prop
  | const  : ∀ v, NoCast (Expr.const v)
  | var    : ∀ x, NoCast (Expr.var x)
  | app    : ∀ f a, NoCast f → NoCast a → NoCast (Expr.app f a)
  | lam    : ∀ x τ body, NoCast body → NoCast (Expr.lam x τ body)
  | loads  : ∀ b, NoCast b → NoCast (Expr.loads b)

/-- A term contains no `loads` sub-expressions and no tainted constants. -/
inductive NoLoads : Expr → Prop
  | const : ∀ v, ¬ isTainted v → NoLoads (Expr.const v)
  | var   : ∀ x, NoLoads (Expr.var x)
  | app   : ∀ f a, NoLoads f → NoLoads a → NoLoads (Expr.app f a)
  | lam   : ∀ x τ body, NoLoads body → NoLoads (Expr.lam x τ body)

/-- Predicate: `e` contains `loads b` as a subterm. -/
inductive HasLoads : Expr → Expr → Prop
  | here    : ∀ b, HasLoads (Expr.loads b) (Expr.loads b)
  | app_l   : ∀ f a b, HasLoads f b → HasLoads (Expr.app f a) b
  | app_r   : ∀ f a b, HasLoads a b → HasLoads (Expr.app f a) b
  | lam_b   : ∀ x τ body b, HasLoads body b → HasLoads (Expr.lam x τ body) b
  | loads_b : ∀ e b, HasLoads e b → HasLoads (Expr.loads e) b
  | cast_b  : ∀ τ e b, HasLoads e b → HasLoads (Expr.cast τ e) b

/-- Predicate: `e` contains a `cast τ (loads b)` subterm. -/
inductive HasCastLoads : Expr → Prop
  | here    : ∀ τ b, HasCastLoads (Expr.cast τ (Expr.loads b))
  | app_l   : ∀ f a, HasCastLoads f → HasCastLoads (Expr.app f a)
  | app_r   : ∀ f a, HasCastLoads a → HasCastLoads (Expr.app f a)
  | lam_b   : ∀ x τ body, HasCastLoads body → HasCastLoads (Expr.lam x τ body)
  | loads_b : ∀ e, HasCastLoads e → HasCastLoads (Expr.loads e)
  | cast_b  : ∀ τ e, HasCastLoads e → HasCastLoads (Expr.cast τ e)

/-- Substitution preserves `NoLoads`. -/
theorem subst_preserves_noloads (e e' : Expr) (x : String) :
    NoLoads e → NoLoads e' → NoLoads (e.subst x e') := by
  sorry

/-- If an expression is typed at a concrete type and contains no cast,
    then it contains no `loads` subterm and no tainted constants. -/
theorem typed_concrete_no_loads (Γ : TypeEnv) (e : Expr) (τ : Ty) :
    Typed Γ e τ → isConcrete τ → NoCast e → NoLoads e := by
  sorry

/-- If an expression contains no `loads` and no tainted constants, then
    its evaluation produces a non-tainted value. -/
theorem eval_not_tainted_without_loads (e : Expr) (v : Value) :
    Eval e v → NoLoads e → ¬ isTainted v := by
  sorry

/-- **Theorem 1** — Pickle soundness for the sound fragment.
    If a closed expression is typed at a concrete type, contains no cast,
    and evaluates to `v`, then `v` is not vulnerable. -/
theorem soundness :
    ∀ (Γ : TypeEnv) (e : Expr) (τ : Ty) (v : Value),
    Typed Γ e τ →
    isConcrete τ →
    NoCast e →
    Eval e v →
    ¬ Vulnerable v := by
  intros Γ e τ v htyped hconc hnc heval
  have hnl : NoLoads e := typed_concrete_no_loads Γ e τ htyped hconc hnc
  have hnt : ¬ isTainted v := eval_not_tainted_without_loads e v heval hnl
  intro hv
  exact hnt hv

/-- **Theorem 2** — `cast` is the only sound escape.
    If a well-typed expression at concrete type contains `loads b`,
    then it must contain a `cast τ (loads b)` somewhere. -/
theorem cast_only_escape :
    ∀ (Γ : TypeEnv) (e : Expr) (τ : Ty) (b : Expr),
    Typed Γ e τ →
    isConcrete τ →
    HasLoads e (Expr.loads b) →
    HasCastLoads e := by
  sorry

end TaintedTypingFramework
