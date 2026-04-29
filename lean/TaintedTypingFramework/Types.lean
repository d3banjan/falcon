import TaintedTypingFramework.Syntax

/-!
# Types.lean — Type rules Γ ⊢ e : τ

The type system tracks `Unsafe[τ]` for tainted data.
`cast` is the only trusted escape from `Unsafe` to a concrete type.
-/

namespace TaintedTypingFramework

/-- Typing environment. -/
def TypeEnv := List (String × Ty)

/-- Type derivations. -/
inductive Typed : TypeEnv → Expr → Ty → Prop
  | T_const_unit   : ∀ Γ, Typed Γ (Expr.const Value.vunit) Ty.unit
  | T_const_bytes  : ∀ Γ s, Typed Γ (Expr.const (Value.vbytes s)) Ty.bytes
  | T_const_int    : ∀ Γ n, Typed Γ (Expr.const (Value.vint n)) Ty.int
  | T_var          : ∀ Γ x τ,
      List.lookup x Γ = some τ →
      Typed Γ (Expr.var x) τ
  | T_lam          : ∀ Γ x τ τ' body,
      Typed ((x, τ) :: Γ) body τ' →
      Typed Γ (Expr.lam x τ body) (Ty.arrow τ τ')
  | T_app          : ∀ Γ f arg τ τ',
      Typed Γ f (Ty.arrow τ τ') →
      Typed Γ arg τ →
      Typed Γ (Expr.app f arg) τ'
  | T_loads        : ∀ Γ b,
      Typed Γ b Ty.bytes →
      Typed Γ (Expr.loads b) (Ty.unsafe_ (Ty.concrete "Any"))
  | T_cast         : ∀ Γ e τ σ,
      Typed Γ e (Ty.unsafe_ σ) →
      Typed Γ (Expr.cast τ e) τ

end TaintedTypingFramework
