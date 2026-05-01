import TaintedTypingFramework.ImportedLoaders
import TaintedTypingFramework.Provenance

/-!
# RealAPIPolicy.lean — enforced real-loader trusted-input policy

This module records the first real Python APIs whose stubs now require trusted
provenance at the call site. The proof shape is intentionally the generic
imported-loader proof shape: promoted inputs may call the loader, but the return
is still `Unsafe[Any]`.
-/

namespace TaintedTypingFramework

def pickleLoadsBytesLoaderSpec : ImportedLoaderSpec where
  path := "pickle.loads"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def torchPathLoaderSpec : ImportedLoaderSpec where
  path := "torch.load"
  inputKind := InputKind.path
  returnTy := Ty.concrete "Checkpoint"
  loadTimeRisk := true

theorem no_raw_bytes_to_real_pickle_loads :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ pickleLoadsBytesLoaderSpec
        (Expr.app pickleLoadsBytesLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ pickleLoadsBytesLoaderSpec payload rfl

theorem no_raw_bytes_to_real_joblib_load :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ joblibPathLoaderSpec
        (Expr.app joblibPathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ joblibPathLoaderSpec payload rfl

theorem no_raw_bytes_to_real_torch_load :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ torchPathLoaderSpec
        (Expr.app torchPathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ torchPathLoaderSpec payload rfl

theorem promoted_bytes_can_call_real_pickle_loads :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ pickleLoadsBytesLoaderSpec
        (Expr.app pickleLoadsBytesLoaderSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) pickleLoadsBytesLoaderSpec promoted

theorem promoted_path_can_call_real_joblib_load :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ joblibPathLoaderSpec
        (Expr.app joblibPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  exact promoted_remote_path_can_call_path_loader Γ path evidence

theorem promoted_path_can_call_real_torch_load :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ torchPathLoaderSpec
        (Expr.app torchPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) torchPathLoaderSpec promoted

theorem real_api_policy_preserves_unsafe_return :
    ∀ Γ spec arg τ,
      spec = pickleLoadsBytesLoaderSpec ∨ spec = joblibPathLoaderSpec ∨ spec = torchPathLoaderSpec →
      ImportedDangerousCall Γ spec (Expr.app spec.expr arg) τ →
      τ = TyUnsafeAny := by
  intro Γ spec arg τ _ hcall
  exact imported_loader_call_returns_unsafe Γ spec (Expr.app spec.expr arg) τ hcall

end TaintedTypingFramework
