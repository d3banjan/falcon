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
  If a well-typed expression contains `loads b` at concrete type,
  then somewhere it must contain a `cast` bridging the gap.
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

/-- **Theorem 1** — Pickle soundness for the sound fragment. -/
theorem soundness :
    ∀ Γ e τ v,
    Typed Γ e τ →
    isConcrete τ →
    NoCast e →
    Eval e v →
    ¬ Vulnerable v := by
  sorry

/-- Predicate: `e` contains `loads b` as a subterm. -/
inductive HasLoads : Expr → Expr → Prop
  | here   : ∀ b, HasLoads (Expr.loads b) (Expr.loads b)
  | app_l  : ∀ f a b, HasLoads f b → HasLoads (Expr.app f a) b
  | app_r  : ∀ f a b, HasLoads a b → HasLoads (Expr.app f a) b
  | lam_b  : ∀ x τ body b, HasLoads body b → HasLoads (Expr.lam x τ body) b
  | loads_b : ∀ e b, HasLoads e b → HasLoads (Expr.loads e) b
  | cast_b : ∀ τ e b, HasLoads e b → HasLoads (Expr.cast τ e) b

/-- Predicate: `e` contains a `cast τ (loads b)` subterm. -/
inductive HasCastLoads : Expr → Prop
  | here   : ∀ τ b, HasCastLoads (Expr.cast τ (Expr.loads b))
  | app_l  : ∀ f a, HasCastLoads f → HasCastLoads (Expr.app f a)
  | app_r  : ∀ f a, HasCastLoads a → HasCastLoads (Expr.app f a)
  | lam_b  : ∀ x τ body, HasCastLoads body → HasCastLoads (Expr.lam x τ body)
  | loads_b : ∀ e, HasCastLoads e → HasCastLoads (Expr.loads e)
  | cast_b : ∀ τ e, HasCastLoads e → HasCastLoads (Expr.cast τ e)

/-- **Theorem 2** — `cast` is the only sound escape. -/
theorem cast_only_escape :
    ∀ Γ e τ b,
    Typed Γ e τ →
    isConcrete τ →
    HasLoads e (Expr.loads b) →
    HasCastLoads e := by
  sorry

end TaintedTypingFramework
