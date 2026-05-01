import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Types
import TaintedTypingFramework.Semantics
import TaintedTypingFramework.Soundness

/-!
# SoundFragment.lean - Replacement syntactic invariant

This module keeps `Soundness.lean` unchanged and states a smaller replacement
fragment that rules out the higher-order counterexamples: no `loads`, no
`cast`, no tainted constants, and no function parameter type containing
`Unsafe[_]`.
-/

namespace TaintedTypingFramework

/-- A type is safe for the replacement sound fragment when it contains no
    `Unsafe[_]` at the top level or under arrows. -/
def NoUnsafeTy : Ty → Prop
  | Ty.unsafe_ _ => False
  | Ty.arrow dom cod => NoUnsafeTy dom ∧ NoUnsafeTy cod
  | _ => True

/-- Values admitted as constants in the replacement fragment. -/
def SafeValue (v : Value) : Prop :=
  ¬ isTainted v

/-- Strong syntactic invariant for the replacement sound fragment.
    There are deliberately no constructors for `loads` or `cast`; lambda
    parameters also cannot have an `Unsafe[_]` type. -/
inductive NoUnsafeSubterms : Expr → Prop
  | const : ∀ v, SafeValue v → NoUnsafeSubterms (Expr.const v)
  | var : ∀ x, NoUnsafeSubterms (Expr.var x)
  | app : ∀ f arg,
      NoUnsafeSubterms f →
      NoUnsafeSubterms arg →
      NoUnsafeSubterms (Expr.app f arg)
  | lam : ∀ x τ body,
      NoUnsafeTy τ →
      NoUnsafeSubterms body →
      NoUnsafeSubterms (Expr.lam x τ body)

/-- The replacement fragment implies the existing `NoLoads` predicate. -/
theorem noUnsafeSubterms_noLoads (e : Expr) :
    NoUnsafeSubterms e → NoLoads e := by
  intro hsafe
  induction hsafe with
  | const v hv =>
      exact NoLoads.const v hv
  | var x =>
      exact NoLoads.var x
  | app f arg _ _ ihf iharg =>
      exact NoLoads.app f arg ihf iharg
  | lam x τ body _ _ ih =>
      exact NoLoads.lam x τ body ih

/-- Replacement soundness lemma: evaluation of an expression in the stronger
    fragment cannot produce a tainted value. -/
theorem eval_not_tainted_noUnsafeSubterms (e : Expr) (v : Value) :
    Eval e v → NoUnsafeSubterms e → ¬ isTainted v := by
  intro heval hsafe
  exact eval_not_tainted_without_loads e v heval (noUnsafeSubterms_noLoads e hsafe)

/-- Direct `loads` expressions are rejected by the replacement fragment. -/
theorem loads_rejected (b : Expr) :
    ¬ NoUnsafeSubterms (Expr.loads b) := by
  intro h
  cases h

/-- Applications of functions accepting unsafe arguments are rejected, even
    when the argument itself contains no `loads`. -/
theorem unsafe_argument_function_rejected :
    ¬ NoUnsafeSubterms
      (Expr.app
        (Expr.lam "x" (Ty.unsafe_ (Ty.concrete "Any")) (Expr.const (Value.vint 0)))
        (Expr.const Value.vunit)) := by
  intro h
  cases h with
  | app _ _ hf _ =>
      cases hf with
      | lam _ _ _ hτ _ =>
          exact hτ

/-- The existing higher-order counterexample shape is outside the replacement
    fragment. -/
theorem typed_concrete_no_loads_counterexample_rejected :
    ¬ NoUnsafeSubterms
      (Expr.app
        (Expr.lam "x" (Ty.unsafe_ (Ty.concrete "Any")) (Expr.const (Value.vint 0)))
        (Expr.loads (Expr.const (Value.vbytes "payload")))) := by
  intro h
  cases h with
  | app _ _ _ harg =>
      exact loads_rejected (Expr.const (Value.vbytes "payload")) harg

end TaintedTypingFramework
