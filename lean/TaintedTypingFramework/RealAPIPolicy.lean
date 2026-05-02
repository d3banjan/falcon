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

def cloudpickleLoadsBytesLoaderSpec : ImportedLoaderSpec where
  path := "cloudpickle.loads"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def cloudpickleLoadBinaryIOLoaderSpec : ImportedLoaderSpec where
  path := "cloudpickle.load"
  inputKind := InputKind.binaryIO
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def dillLoadsBytesLoaderSpec : ImportedLoaderSpec where
  path := "dill.loads"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def dillLoadBinaryIOLoaderSpec : ImportedLoaderSpec where
  path := "dill.load"
  inputKind := InputKind.binaryIO
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def pandasReadPicklePathLoaderSpec : ImportedLoaderSpec where
  path := "pandas.read_pickle"
  inputKind := InputKind.path
  returnTy := Ty.concrete "DataFrame"
  loadTimeRisk := true

def pandasIOReadPicklePathLoaderSpec : ImportedLoaderSpec where
  path := "pandas.io.pickle.read_pickle"
  inputKind := InputKind.path
  returnTy := Ty.concrete "DataFrame"
  loadTimeRisk := true

def torchPathLoaderSpec : ImportedLoaderSpec where
  path := "torch.load"
  inputKind := InputKind.path
  returnTy := Ty.concrete "Checkpoint"
  loadTimeRisk := true

def langchainCommunityFaissBytesLoaderSpec : ImportedLoaderSpec where
  path := "langchain_community.vectorstores.faiss.FAISS.deserialize_from_bytes"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def langchainCommunityFaissPathLoaderSpec : ImportedLoaderSpec where
  path := "langchain_community.vectorstores.faiss.FAISS.load_local"
  inputKind := InputKind.path
  returnTy := Ty.concrete "FAISS"
  loadTimeRisk := true

def langchainLegacyFaissBytesLoaderSpec : ImportedLoaderSpec where
  path := "langchain.vectorstores.faiss.FAISS.deserialize_from_bytes"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "Any"
  loadTimeRisk := true

def langchainLegacyFaissPathLoaderSpec : ImportedLoaderSpec where
  path := "langchain.vectorstores.faiss.FAISS.load_local"
  inputKind := InputKind.path
  returnTy := Ty.concrete "FAISS"
  loadTimeRisk := true

def pipecatLivekitFrameDeserializeSpec : ImportedLoaderSpec where
  path := "pipecat.serializers.livekit.LivekitFrameSerializer.deserialize"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "Frame"
  loadTimeRisk := true

def torchMusaCompareSingleOpSpec : ImportedLoaderSpec where
  path := "torch_musa.utils.compare_tool.compare_for_single_op"
  inputKind := InputKind.path
  returnTy := Ty.concrete "Comparison"
  loadTimeRisk := true

def torchMusaNanInfTrackSingleOpSpec : ImportedLoaderSpec where
  path := "torch_musa.utils.compare_tool.nan_inf_track_for_single_op"
  inputKind := InputKind.path
  returnTy := Ty.concrete "Comparison"
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

theorem no_raw_bytes_to_real_cloudpickle_loads :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ cloudpickleLoadsBytesLoaderSpec
        (Expr.app cloudpickleLoadsBytesLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ cloudpickleLoadsBytesLoaderSpec payload rfl

theorem no_raw_bytes_to_real_cloudpickle_load :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ cloudpickleLoadBinaryIOLoaderSpec
        (Expr.app cloudpickleLoadBinaryIOLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_binary_io_loader Γ cloudpickleLoadBinaryIOLoaderSpec payload rfl

theorem no_raw_bytes_to_real_dill_loads :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ dillLoadsBytesLoaderSpec
        (Expr.app dillLoadsBytesLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ dillLoadsBytesLoaderSpec payload rfl

theorem no_raw_bytes_to_real_dill_load :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ dillLoadBinaryIOLoaderSpec
        (Expr.app dillLoadBinaryIOLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_binary_io_loader Γ dillLoadBinaryIOLoaderSpec payload rfl

theorem no_raw_bytes_to_real_pandas_read_pickle :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ pandasReadPicklePathLoaderSpec
        (Expr.app pandasReadPicklePathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ pandasReadPicklePathLoaderSpec payload rfl

theorem no_raw_bytes_to_real_pandas_io_read_pickle :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ pandasIOReadPicklePathLoaderSpec
        (Expr.app pandasIOReadPicklePathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ pandasIOReadPicklePathLoaderSpec payload rfl

theorem no_raw_bytes_to_real_torch_load :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ torchPathLoaderSpec
        (Expr.app torchPathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ torchPathLoaderSpec payload rfl

theorem no_raw_bytes_to_langchain_community_faiss_deserialize :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ langchainCommunityFaissBytesLoaderSpec
        (Expr.app langchainCommunityFaissBytesLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ langchainCommunityFaissBytesLoaderSpec payload rfl

theorem no_raw_bytes_to_langchain_community_faiss_load_local :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ langchainCommunityFaissPathLoaderSpec
        (Expr.app langchainCommunityFaissPathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ langchainCommunityFaissPathLoaderSpec payload rfl

theorem no_raw_bytes_to_langchain_legacy_faiss_deserialize :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ langchainLegacyFaissBytesLoaderSpec
        (Expr.app langchainLegacyFaissBytesLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ langchainLegacyFaissBytesLoaderSpec payload rfl

theorem no_raw_bytes_to_langchain_legacy_faiss_load_local :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ langchainLegacyFaissPathLoaderSpec
        (Expr.app langchainLegacyFaissPathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ langchainLegacyFaissPathLoaderSpec payload rfl

theorem no_raw_bytes_to_pipecat_livekit_frame_deserialize :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ pipecatLivekitFrameDeserializeSpec
        (Expr.app pipecatLivekitFrameDeserializeSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ pipecatLivekitFrameDeserializeSpec payload rfl

theorem no_raw_bytes_to_torch_musa_compare_single_op :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ torchMusaCompareSingleOpSpec
        (Expr.app torchMusaCompareSingleOpSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ torchMusaCompareSingleOpSpec payload rfl

theorem no_raw_bytes_to_torch_musa_nan_inf_track_single_op :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ torchMusaNanInfTrackSingleOpSpec
        (Expr.app torchMusaNanInfTrackSingleOpSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ torchMusaNanInfTrackSingleOpSpec payload rfl

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

theorem promoted_bytes_can_call_real_cloudpickle_loads :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ cloudpickleLoadsBytesLoaderSpec
        (Expr.app cloudpickleLoadsBytesLoaderSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) cloudpickleLoadsBytesLoaderSpec promoted

theorem trusted_binary_io_can_call_real_cloudpickle_load :
    ∀ Γ handle,
      ImportedDangerousCall Γ cloudpickleLoadBinaryIOLoaderSpec
        (Expr.app cloudpickleLoadBinaryIOLoaderSpec.expr (trustedBinaryIOExpr handle)) TyUnsafeAny := by
  intro Γ handle
  exact trusted_imported_input_still_returns_unsafe Γ cloudpickleLoadBinaryIOLoaderSpec
    (trustedBinaryIOExpr handle) (TrustedInputTyped.T_trusted_binary_io Γ handle)

theorem promoted_bytes_can_call_real_dill_loads :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ dillLoadsBytesLoaderSpec
        (Expr.app dillLoadsBytesLoaderSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) dillLoadsBytesLoaderSpec promoted

theorem trusted_binary_io_can_call_real_dill_load :
    ∀ Γ handle,
      ImportedDangerousCall Γ dillLoadBinaryIOLoaderSpec
        (Expr.app dillLoadBinaryIOLoaderSpec.expr (trustedBinaryIOExpr handle)) TyUnsafeAny := by
  intro Γ handle
  exact trusted_imported_input_still_returns_unsafe Γ dillLoadBinaryIOLoaderSpec
    (trustedBinaryIOExpr handle) (TrustedInputTyped.T_trusted_binary_io Γ handle)

theorem promoted_path_can_call_real_joblib_load :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ joblibPathLoaderSpec
        (Expr.app joblibPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  exact promoted_remote_path_can_call_path_loader Γ path evidence

theorem promoted_path_can_call_real_pandas_read_pickle :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ pandasReadPicklePathLoaderSpec
        (Expr.app pandasReadPicklePathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) pandasReadPicklePathLoaderSpec promoted

theorem promoted_path_can_call_real_pandas_io_read_pickle :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ pandasIOReadPicklePathLoaderSpec
        (Expr.app pandasIOReadPicklePathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) pandasIOReadPicklePathLoaderSpec promoted

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

theorem promoted_bytes_can_call_langchain_community_faiss_deserialize :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ langchainCommunityFaissBytesLoaderSpec
        (Expr.app langchainCommunityFaissBytesLoaderSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) langchainCommunityFaissBytesLoaderSpec promoted

theorem promoted_path_can_call_langchain_community_faiss_load_local :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ langchainCommunityFaissPathLoaderSpec
        (Expr.app langchainCommunityFaissPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) langchainCommunityFaissPathLoaderSpec promoted

theorem promoted_bytes_can_call_langchain_legacy_faiss_deserialize :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ langchainLegacyFaissBytesLoaderSpec
        (Expr.app langchainLegacyFaissBytesLoaderSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) langchainLegacyFaissBytesLoaderSpec promoted

theorem promoted_path_can_call_langchain_legacy_faiss_load_local :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ langchainLegacyFaissPathLoaderSpec
        (Expr.app langchainLegacyFaissPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) langchainLegacyFaissPathLoaderSpec promoted

theorem promoted_bytes_can_call_pipecat_livekit_frame_deserialize :
    ∀ Γ payload (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ pipecatLivekitFrameDeserializeSpec
        (Expr.app pipecatLivekitFrameDeserializeSpec.expr (trustedBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload evidence
  have promoted : PromotedInput Γ (networkBytesExpr payload) evidence
      (trustedBytesExpr payload) TyTrustedBytes :=
    PromotedInput.bytes Γ IngressSource.network payload evidence
  exact promoted_input_can_call_imported_loader Γ (networkBytesExpr payload) evidence
    (trustedBytesExpr payload) pipecatLivekitFrameDeserializeSpec promoted

theorem promoted_path_can_call_torch_musa_compare_single_op :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ torchMusaCompareSingleOpSpec
        (Expr.app torchMusaCompareSingleOpSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) torchMusaCompareSingleOpSpec promoted

theorem promoted_path_can_call_torch_musa_nan_inf_track_single_op :
    ∀ Γ path (_evidence : PromotionEvidence),
      ImportedDangerousCall Γ torchMusaNanInfTrackSingleOpSpec
        (Expr.app torchMusaNanInfTrackSingleOpSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path evidence
  have promoted : PromotedInput Γ (remoteArtifactPathExpr path) evidence
      (trustedPathExpr path) TyTrustedPath :=
    PromotedInput.path Γ IngressSource.remoteArtifact path evidence
  exact promoted_input_can_call_imported_loader Γ (remoteArtifactPathExpr path) evidence
    (trustedPathExpr path) torchMusaNanInfTrackSingleOpSpec promoted

theorem real_api_policy_preserves_unsafe_return :
    ∀ Γ spec arg τ,
      spec = pickleLoadsBytesLoaderSpec ∨
        spec = cloudpickleLoadsBytesLoaderSpec ∨
        spec = cloudpickleLoadBinaryIOLoaderSpec ∨
        spec = dillLoadsBytesLoaderSpec ∨
        spec = dillLoadBinaryIOLoaderSpec ∨
        spec = joblibPathLoaderSpec ∨
        spec = pandasReadPicklePathLoaderSpec ∨
        spec = pandasIOReadPicklePathLoaderSpec ∨
        spec = torchPathLoaderSpec ∨
        spec = langchainCommunityFaissBytesLoaderSpec ∨
        spec = langchainCommunityFaissPathLoaderSpec ∨
        spec = langchainLegacyFaissBytesLoaderSpec ∨
        spec = langchainLegacyFaissPathLoaderSpec ∨
        spec = pipecatLivekitFrameDeserializeSpec ∨
        spec = torchMusaCompareSingleOpSpec ∨
        spec = torchMusaNanInfTrackSingleOpSpec →
      ImportedDangerousCall Γ spec (Expr.app spec.expr arg) τ →
      τ = TyUnsafeAny := by
  intro Γ spec arg τ _ hcall
  exact imported_loader_call_returns_unsafe Γ spec (Expr.app spec.expr arg) τ hcall

end TaintedTypingFramework
