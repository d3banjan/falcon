import TaintedTypingFramework.TrustedInputs

/-!
# BackendEvidence.lean — common taint result from checker backends

Falcon can learn about a dangerous deserialization edge from different
backends: packaged stubs, AST semantic-policy rules, or application type
evidence. This module records that those backends justify the same quarantine
result and never declassify `Unsafe[Any]`.
-/

namespace TaintedTypingFramework

/-- Evidence produced by a packaged stub annotation. -/
inductive StubEvidence : Expr → Prop
  | unsafeReturn : ∀ e, StubEvidence e

/-- Evidence produced by an AST semantic-policy rule such as unsafe config. -/
inductive ASTEvidence : Expr → Prop
  | unsafeConfig : ∀ e, ASTEvidence e

/-- Evidence produced from application-level type information. -/
inductive AppTypeEvidence : Expr → Prop
  | unsafeFlow : ∀ e, AppTypeEvidence e

/-- A backend-independent evidence wrapper. -/
inductive BackendEvidence : Expr → Prop
  | stub : ∀ {e}, StubEvidence e → BackendEvidence e
  | ast : ∀ {e}, ASTEvidence e → BackendEvidence e
  | appType : ∀ {e}, AppTypeEvidence e → BackendEvidence e

/-- Falcon's taint result for a backend-confirmed unsafe edge. -/
inductive FalconTaint : Expr → Ty → Prop
  | unsafeAny : ∀ {e}, BackendEvidence e → FalconTaint e TyUnsafeAny

theorem stub_evidence_justifies_falcon_taint :
    ∀ e, StubEvidence e → FalconTaint e TyUnsafeAny := by
  intro e h
  exact FalconTaint.unsafeAny (BackendEvidence.stub h)

theorem ast_evidence_justifies_falcon_taint :
    ∀ e, ASTEvidence e → FalconTaint e TyUnsafeAny := by
  intro e h
  exact FalconTaint.unsafeAny (BackendEvidence.ast h)

theorem app_type_evidence_justifies_falcon_taint :
    ∀ e, AppTypeEvidence e → FalconTaint e TyUnsafeAny := by
  intro e h
  exact FalconTaint.unsafeAny (BackendEvidence.appType h)

theorem backend_evidence_taint_is_unsafe :
    ∀ e τ, BackendEvidence e → FalconTaint e τ → τ = TyUnsafeAny := by
  intro e τ _ htaint
  cases htaint
  rfl

theorem backend_evidence_does_not_declassify_to_concrete :
    ∀ e name, BackendEvidence e → ¬ FalconTaint e (Ty.concrete name) := by
  intro e name evidence htaint
  have h : Ty.concrete name = TyUnsafeAny :=
    backend_evidence_taint_is_unsafe e (Ty.concrete name) evidence htaint
  cases h

end TaintedTypingFramework
