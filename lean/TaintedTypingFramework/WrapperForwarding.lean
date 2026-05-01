import TaintedTypingFramework.BackendEvidence
import TaintedTypingFramework.ConditionalConfig
import TaintedTypingFramework.ImportedLoaders
import TaintedTypingFramework.TrustedInputs

/-!
# WrapperForwarding.lean — wrapper-level taint forwarding

Wrapper APIs in the checker may report evidence that a wrapper forwards either
trusted input or unsafe config into a dangerous deserialization path.  This module
models that evidence as a small proof family that always justifies
`FalconTaint ... TyUnsafeAny`.
-/

namespace TaintedTypingFramework

/-- A wrapper evidence item records the wrapper expression and the delegated loader spec. -/
structure WrapperForwarding where
  Γ : TypeEnv
  wrapperExpr : Expr
  loaderSpec : ImportedLoaderSpec
  forwardedArg : Expr

/-- Evidence that a wrapper forwarding edge reaches a dangerous imported loader. -/
inductive WrapperEvidence : WrapperForwarding → Prop
  | trustedInput :
      ∀ {w},
        TrustedInputTyped w.Γ w.forwardedArg w.loaderSpec.inputKind.trustedTy →
        WrapperEvidence w
  | trustedInputWithUnsafeConfig :
      ∀ {w cfg},
        TrustedInputTyped w.Γ w.forwardedArg w.loaderSpec.inputKind.trustedTy →
        ConditionalConfigEvidence cfg →
        WrapperEvidence w

/-- Wrapper evidence is a kind of application evidence. -/
theorem wrapper_evidence_is_app_type :
    ∀ {w}, WrapperEvidence w → AppTypeEvidence w.wrapperExpr := by
  intro w h
  cases h with
  | trustedInput _ =>
    exact AppTypeEvidence.unsafeFlow w.wrapperExpr
  | trustedInputWithUnsafeConfig _ _ =>
    exact AppTypeEvidence.unsafeFlow w.wrapperExpr

/-- Wrapper forwarding evidence always concludes `Unsafe[Any]`. -/
theorem wrapper_evidence_justifies_falcon_taint :
    ∀ {w}, WrapperEvidence w → FalconTaint w.wrapperExpr TyUnsafeAny := by
  intro w h
  exact FalconTaint.unsafeAny (BackendEvidence.appType (wrapper_evidence_is_app_type (w := w) h))

/-- Wrapper forwarding evidence cannot declassify to concrete types. -/
theorem wrapper_evidence_does_not_declassify :
    ∀ {w name}, WrapperEvidence w → ¬ FalconTaint w.wrapperExpr (Ty.concrete name) := by
  intro w name h hTaint
  have hUnsafe :
      Ty.concrete name = TyUnsafeAny :=
    backend_evidence_taint_is_unsafe w.wrapperExpr (Ty.concrete name)
      (BackendEvidence.appType (wrapper_evidence_is_app_type (w := w) h)) hTaint
  cases hUnsafe

/-- A wrapper evidence witness can be re-used as an `ImportedDangerousCall` precondition. -/
theorem wrapper_evidence_entails_imported_call :
    ∀ {w}, WrapperEvidence w →
      ImportedDangerousCall w.Γ w.loaderSpec
        (Expr.app w.loaderSpec.expr w.forwardedArg) TyUnsafeAny := by
  intro w h
  cases h with
  | trustedInput hArg =>
    exact ImportedDangerousCall.call hArg
  | trustedInputWithUnsafeConfig hArg hcfg =>
    exact ImportedDangerousCall.call hArg

end TaintedTypingFramework
