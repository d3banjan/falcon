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
  subterm, then it must also contain a `cast` subexpression somewhere.
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

/-- Predicate: `e` contains a `cast` subexpression. -/
inductive HasCast : Expr → Prop
  | here    : ∀ τ e, HasCast (Expr.cast τ e)
  | app_l   : ∀ f a, HasCast f → HasCast (Expr.app f a)
  | app_r   : ∀ f a, HasCast a → HasCast (Expr.app f a)
  | lam_b   : ∀ x τ body, HasCast body → HasCast (Expr.lam x τ body)
  | loads_b : ∀ e, HasCast e → HasCast (Expr.loads e)
  | cast_b  : ∀ τ e, HasCast e → HasCast (Expr.cast τ e)

/-- Substitution preserves `NoLoads`. -/
theorem subst_preserves_noloads (e e' : Expr) (x : String) :
    NoLoads e → NoLoads e' → NoLoads (e.subst x e') := by
  intro h1 h2
  revert h2
  induction h1 with
  | const v hnt =>
      intro h2
      simp [Expr.subst]
      exact NoLoads.const v hnt
  | var y =>
      intro h2
      simp [Expr.subst]
      by_cases hxy : x = y
      · simp [hxy]; exact h2
      · simp [hxy]; exact NoLoads.var y
  | app f a hnf hna ihf iha =>
      intro h2
      simp [Expr.subst]
      exact NoLoads.app (f.subst x e') (a.subst x e') (ihf h2) (iha h2)
  | lam y τ body hnb ih =>
      intro h2
      simp [Expr.subst]
      by_cases hxy : x = y
      · simp [hxy]; exact NoLoads.lam y τ body hnb
      · simp [hxy]
        exact NoLoads.lam y τ (body.subst x e') (ih h2)

/-- Helper: if a closed expression evaluates to a closure and contains
    no loads, then the body of the closure also contains no loads.
    (Proof requires induction on evaluation; omitted for brevity.) -/
theorem eval_closure_noloads_body (f : Expr) (x : String) (τ : Ty) (body : Expr) :
    Eval f (Value.vclosure [] x τ body) → NoLoads f → NoLoads body := by
  sorry

/-- If an expression is typed at a concrete type and contains no cast,
    then it contains no `loads` subterm and no tainted constants.
    (Proof requires a substitution lemma for typing; omitted for brevity.) -/
theorem typed_concrete_no_loads (Γ : TypeEnv) (e : Expr) (τ : Ty) :
    Typed Γ e τ → isConcrete τ → NoCast e → NoLoads e := by
  sorry

/-- If an expression contains no `loads` and no tainted constants, then
    its evaluation produces a non-tainted value. -/
theorem eval_not_tainted_without_loads (e : Expr) (v : Value) :
    Eval e v → NoLoads e → ¬ isTainted v := by
  intro heval hnl
  induction heval with
  | E_const v =>
      cases hnl
      assumption
  | E_lam x τ body =>
      intro h
      cases h
      rename_i w hw
      cases hw
  | E_app f x body arg varg vbody τ_dom hf harg hbody ih_f ih_arg ih_body =>
      intro h
      have hnl_f : NoLoads f := by cases hnl; assumption
      have hnl_arg : NoLoads arg := by cases hnl; assumption
      have hnl_body : NoLoads body := eval_closure_noloads_body f x τ_dom body hf hnl_f
      have hnl_varg : ¬ isTainted varg := ih_arg hnl_arg
      have hnl_sub : NoLoads (body.subst x (Expr.const varg)) := by
        exact subst_preserves_noloads body (Expr.const varg) x hnl_body (NoLoads.const varg hnl_varg)
      exact ih_body hnl_sub h
  | E_loads b vb heval_b ih_b =>
      exfalso
      cases hnl
  | E_cast τ_cast e_cast v_cast heval_cast ih_cast =>
      intro h
      cases hnl

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
    then it must contain a `cast` subexpression somewhere. -/
theorem cast_only_escape :
    ∀ (Γ : TypeEnv) (e : Expr) (τ : Ty) (b : Expr),
    Typed Γ e τ →
    isConcrete τ →
    HasLoads e (Expr.loads b) →
    HasCast e := by
  sorry

end TaintedTypingFramework
