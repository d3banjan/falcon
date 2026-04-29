import TaintedTypingFramework.Syntax

/-!
# Semantics.lean — Big-step operational semantics (closed terms)

`Eval e v` means closed expression `e` evaluates to value `v`.

Key rules:
- `loads b` always succeeds with a tainted attacker-controlled value.
- `cast τ e` is the identity at runtime.
- function application uses naïve substitution (sufficient for this model).
-/

namespace TaintedTypingFramework

/-- Big-step evaluation relation for closed expressions. -/
inductive Eval : Expr → Value → Prop
  | E_const : ∀ v, Eval (Expr.const v) v
  | E_lam   : ∀ x τ body, Eval (Expr.lam x τ body) (Value.vclosure [] x τ body)
  | E_app   : ∀ f x body arg varg vbody τ,
      Eval f (Value.vclosure [] x τ body) →
      Eval arg varg →
      Eval (Expr.subst body x (Expr.const varg)) vbody →
      Eval (Expr.app f arg) vbody
  | E_loads : ∀ b vb, Eval b vb → Eval (Expr.loads b) (Value.tainted vb)
  | E_cast  : ∀ τ e v, Eval e v → Eval (Expr.cast τ e) v

end TaintedTypingFramework
