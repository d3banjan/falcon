import TaintedTypingFramework.ImportedLoaders
import TaintedTypingFramework.Ingress

/-!
# Provenance.lean — promotion boundary for trusted loader inputs

This module models the TrustedBytes/TrustedPath/TrustedArtifact line directly:
untrusted ingress cannot call an imported dangerous loader until a separate
promotion step produces a trusted input type. Promotion only satisfies the
loader precondition; it never declassifies the loader's `Unsafe[Any]` result.
-/

namespace TaintedTypingFramework

/-- Evidence families that may justify a trusted-input promotion. -/
inductive PromotionEvidence : Type
  | manualReview
  | sha256
  | signature
  deriving Repr, DecidableEq

/-- A promoted input records the original expression, evidence, and trusted expression. -/
inductive PromotedInput : TypeEnv → Expr → PromotionEvidence → Expr → Ty → Prop
  | bytes : ∀ Γ source payload evidence,
      PromotedInput Γ (untrustedBytesExpr source payload) evidence
        (trustedBytesExpr payload) TyTrustedBytes
  | path : ∀ Γ source path evidence,
      PromotedInput Γ (untrustedPathExpr source path) evidence
        (trustedPathExpr path) TyTrustedPath
  | artifact : ∀ Γ locator evidence,
      PromotedInput Γ (remoteArtifactExpr locator) evidence
        (trustedArtifactExpr locator) TyTrustedArtifact

theorem promoted_input_is_trusted :
    ∀ Γ raw evidence trusted τ,
      PromotedInput Γ raw evidence trusted τ →
      TrustedInputTyped Γ trusted τ := by
  intro Γ raw evidence trusted τ h
  cases h with
  | bytes source payload evidence =>
      exact TrustedInputTyped.T_trusted_bytes Γ payload
  | path source path evidence =>
      exact TrustedInputTyped.T_trusted_path Γ path
  | artifact locator evidence =>
      exact TrustedInputTyped.T_trusted_artifact Γ locator

theorem promoted_input_can_call_imported_loader :
    ∀ Γ raw evidence trusted spec,
      PromotedInput Γ raw evidence trusted spec.inputKind.trustedTy →
      ImportedDangerousCall Γ spec (Expr.app spec.expr trusted) TyUnsafeAny := by
  intro Γ raw evidence trusted spec h
  exact ImportedDangerousCall.call (promoted_input_is_trusted Γ raw evidence trusted spec.inputKind.trustedTy h)

theorem promotion_preserves_unsafe_return :
    ∀ Γ raw evidence trusted spec τ,
      PromotedInput Γ raw evidence trusted spec.inputKind.trustedTy →
      ImportedDangerousCall Γ spec (Expr.app spec.expr trusted) τ →
      τ = TyUnsafeAny := by
  intro Γ raw evidence trusted spec τ _ hcall
  exact imported_loader_call_returns_unsafe Γ spec (Expr.app spec.expr trusted) τ hcall

theorem unpromoted_network_bytes_rejected_by_bytes_loader :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ horovodCloudpickleBytesLoaderSpec
        (Expr.app horovodCloudpickleBytesLoaderSpec.expr (networkBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload h
  have htrusted : TrustedInputTyped Γ (networkBytesExpr payload) TyTrustedBytes :=
    imported_loader_input_must_be_trusted Γ horovodCloudpickleBytesLoaderSpec
      (networkBytesExpr payload) h
  exact untrusted_ingress_bytes_not_trusted_bytes Γ IngressSource.network payload htrusted

theorem promoted_network_bytes_can_call_bytes_loader :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ horovodCloudpickleBytesLoaderSpec
        (Expr.app horovodCloudpickleBytesLoaderSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) horovodCloudpickleBytesLoaderSpec promoted

theorem unpromoted_remote_path_rejected_by_path_loader :
    ∀ Γ path,
      ¬ ImportedDangerousCall Γ joblibPathLoaderSpec
        (Expr.app joblibPathLoaderSpec.expr (remoteArtifactPathExpr path)) TyUnsafeAny := by
  intro Γ path h
  have htrusted : TrustedInputTyped Γ (remoteArtifactPathExpr path) TyTrustedPath :=
    imported_loader_input_must_be_trusted Γ joblibPathLoaderSpec
      (remoteArtifactPathExpr path) h
  exact untrusted_ingress_path_not_trusted_path Γ IngressSource.remoteArtifact path htrusted

theorem promoted_remote_path_can_call_path_loader :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ joblibPathLoaderSpec
        (Expr.app joblibPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) joblibPathLoaderSpec promoted

theorem unpromoted_remote_artifact_rejected_by_artifact_loader :
    ∀ Γ locator,
      ¬ ImportedDangerousCall Γ modelArtifactLoaderSpec
        (Expr.app modelArtifactLoaderSpec.expr (remoteArtifactExpr locator)) TyUnsafeAny := by
  intro Γ locator h
  have htrusted : TrustedInputTyped Γ (remoteArtifactExpr locator) TyTrustedArtifact :=
    imported_loader_input_must_be_trusted Γ modelArtifactLoaderSpec
      (remoteArtifactExpr locator) h
  exact untrusted_remote_artifact_not_trusted_artifact Γ locator htrusted

theorem promoted_remote_artifact_can_call_artifact_loader :
    ∀ Γ locator (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ modelArtifactLoaderSpec
        (Expr.app modelArtifactLoaderSpec.expr (trustedArtifactExpr locator)) TyUnsafeAny := by
  intro Γ locator evidence
  have promoted : PromotedInput Γ (remoteArtifactExpr locator) evidence
      (trustedArtifactExpr locator) TyTrustedArtifact :=
    PromotedInput.artifact Γ locator evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactExpr locator) evidence
    (trustedArtifactExpr locator) modelArtifactLoaderSpec promoted

end TaintedTypingFramework
