import TaintedTypingFramework.BackendEvidence

/-!
# ConditionalConfig.lean — unsafe static-config literals as policy evidence

This module models a policy backend rule: certain deserialization-related boolean
flags in configuration literals are evidence of risk. Such evidence justifies
`FalconTaint` at `TyUnsafeAny` through `ASTEvidence`, without any
declassification to a concrete type.
-/

namespace TaintedTypingFramework

/-- A canonical syntax node for unsafe config-literal flags. -/
def conditionalConfigExpr (flag : String) (value : String) : Expr :=
  Expr.const (Value.vconcrete "conditional-config-flag" (Value.vconcrete flag (Value.vbytes value)))

def allow_pickle_true : Expr := conditionalConfigExpr "allow_pickle" "True"
def safe_false : Expr := conditionalConfigExpr "safe" "False"
def remote_exec_true : Expr := conditionalConfigExpr "remote_exec" "True"
def trust_remote_code_true : Expr := conditionalConfigExpr "trust_remote_code" "True"

/-- Evidence that a specific unsafe config literal occurred. -/
inductive ConditionalConfigEvidence : Expr → Prop
  | allow_pickle_true : ConditionalConfigEvidence allow_pickle_true
  | safe_false : ConditionalConfigEvidence safe_false
  | remote_exec_true : ConditionalConfigEvidence remote_exec_true
  | trust_remote_code_true : ConditionalConfigEvidence trust_remote_code_true

/-- All unsafe-config evidence is an AST evidence source in the backend model. -/
theorem conditional_config_is_ast_evidence :
    ∀ e, ConditionalConfigEvidence e → ASTEvidence e := by
  intro e h
  cases h <;> simp [ASTEvidence.unsafeConfig]

/-- Unsafe config flags justify taint as `Unsafe[Any]`. -/
theorem conditional_config_justifies_falcon_taint :
    ∀ e, ConditionalConfigEvidence e → FalconTaint e TyUnsafeAny := by
  intro e h
  exact FalconTaint.unsafeAny (BackendEvidence.ast (conditional_config_is_ast_evidence e h))

/-- This backend path does not declassify unsafe config evidence to concrete types. -/
theorem conditional_config_does_not_declassify :
    ∀ e name, ConditionalConfigEvidence e → ¬ FalconTaint e (Ty.concrete name) := by
  intro e name hconfig htaint
  exact
    backend_evidence_does_not_declassify_to_concrete e name
      (BackendEvidence.ast (conditional_config_is_ast_evidence e hconfig)) htaint

theorem allow_pickle_true_unsafe :
    FalconTaint allow_pickle_true TyUnsafeAny := by
  exact conditional_config_justifies_falcon_taint allow_pickle_true ConditionalConfigEvidence.allow_pickle_true

theorem safe_false_unsafe :
    FalconTaint safe_false TyUnsafeAny := by
  exact conditional_config_justifies_falcon_taint safe_false ConditionalConfigEvidence.safe_false

theorem remote_exec_true_unsafe :
    FalconTaint remote_exec_true TyUnsafeAny := by
  exact conditional_config_justifies_falcon_taint remote_exec_true ConditionalConfigEvidence.remote_exec_true

theorem trust_remote_code_true_unsafe :
    FalconTaint trust_remote_code_true TyUnsafeAny := by
  exact conditional_config_justifies_falcon_taint trust_remote_code_true ConditionalConfigEvidence.trust_remote_code_true

end TaintedTypingFramework
