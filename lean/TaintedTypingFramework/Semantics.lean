import TaintedTypingFramework.Syntax

/-!
# Semantics.lean — Big-step operational semantics

`Eval e v` means expression `e` evaluates to value `v`.

Key rules:
- `loads b` always succeeds with a tainted attacker-controlled value.
- `cast τ e` is the identity at runtime.
- function application is standard call-by-value.
-/

namespace TaintedTypingFramework

/-- Big-step evaluation relation. -/
inductive Eval : Expr → Value → Prop
  | E_const  : ∀ v, Eval (Expr.const v) v
  | E_var    : ∀ env x v,
      List.lookup x env = some v →
      Eval (Expr.var x) v
  | E_lam    : ∀ env x τ body,
      Eval (Expr.lam x τ body) (Value.vclosure env x τ body)
  | E_app    : ∀ env f x body arg varg vbody τ,
      Eval f (Value.vclosure env x τ body) →
      Eval arg varg →
      Eval (Expr.subst body x (Expr.const varg)) vbody →
      Eval (Expr.app f arg) vbody
  | E_loads  : ∀ b vb,
      Eval b vb →
      Eval (Expr.loads b) (Value.tainted vb)
  | E_cast   : ∀ τ e v,
      Eval e v →
      Eval (Expr.cast τ e) v

end TaintedTypingFramework
