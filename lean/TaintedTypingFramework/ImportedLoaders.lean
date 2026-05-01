import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Types
import TaintedTypingFramework.TrustedInputs

/-!
# ImportedLoaders.lean — generic imported-loader model

This module models dangerous imported loaders by their code path and a compact
specification, instead of adding a new Lean constructor for every library API.
-/

namespace TaintedTypingFramework

/-- The external input shape accepted by an imported loader. -/
inductive InputKind : Type
  | bytes
  | path
  | binaryIO
  | artifact
  deriving Repr, DecidableEq

/-- The trusted input type required before an imported loader may be called. -/
def InputKind.trustedTy : InputKind → Ty
  | InputKind.bytes => TyTrustedBytes
  | InputKind.path => TyTrustedPath
  | InputKind.binaryIO => TyTrustedBinaryIO
  | InputKind.artifact => TyTrustedArtifact

abbrev ImportedPath := String

/-- Generic metadata for a dangerous loader reachable at an imported code path. -/
structure ImportedLoaderSpec where
  path : ImportedPath
  inputKind : InputKind
  returnTy : Ty := TyUnsafeAny
  loadTimeRisk : Bool

def ImportedLoaderSpec.expr (spec : ImportedLoaderSpec) : Expr :=
  Expr.const (Value.vconcrete "imported-loader" (Value.vconcrete spec.path Value.vunit))

/-- Dangerous calls to imported loaders.

The spec records the apparent imported return type, but this safety model keeps
all successful dangerous-loader calls quarantined as `Unsafe[Any]`.
-/
inductive ImportedDangerousCall : TypeEnv → ImportedLoaderSpec → Expr → Ty → Prop
  | call : ∀ {Γ spec arg},
      TrustedInputTyped Γ arg spec.inputKind.trustedTy →
      ImportedDangerousCall Γ spec (Expr.app spec.expr arg) TyUnsafeAny

/-- Imported dangerous-loader calls can only be formed with the spec's trusted input type. -/
theorem imported_loader_input_must_be_trusted :
    ∀ Γ spec arg,
      ImportedDangerousCall Γ spec (Expr.app spec.expr arg) TyUnsafeAny →
      TrustedInputTyped Γ arg spec.inputKind.trustedTy := by
  intro Γ spec arg h
  cases h with
  | call harg => exact harg

/-- The generic imported-loader judgment never returns the spec's apparent type directly. -/
theorem imported_loader_call_returns_unsafe :
    ∀ Γ spec e τ,
      ImportedDangerousCall Γ spec e τ →
      τ = TyUnsafeAny := by
  intro Γ spec e τ h
  cases h
  rfl

/-- Trusted input satisfies the precondition but does not erase the unsafe return. -/
theorem trusted_imported_input_still_returns_unsafe :
    ∀ Γ spec arg,
      TrustedInputTyped Γ arg spec.inputKind.trustedTy →
      ImportedDangerousCall Γ spec (Expr.app spec.expr arg) TyUnsafeAny := by
  intro Γ spec arg harg
  exact ImportedDangerousCall.call harg

/-- Raw bytes cannot call a path loader. -/
theorem raw_bytes_cannot_call_path_loader :
    ∀ Γ spec payload,
      spec.inputKind = InputKind.path →
      ¬ ImportedDangerousCall Γ spec
        (Expr.app spec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ spec payload hkind hcall
  have htrusted : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) spec.inputKind.trustedTy :=
    imported_loader_input_must_be_trusted Γ spec (Expr.const (Value.vbytes payload)) hcall
  have hpath : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) TyTrustedPath := by
    simpa [InputKind.trustedTy, hkind] using htrusted
  exact untrusted_bytes_not_typed_as_trusted_path Γ payload hpath

/-- Raw bytes cannot call an artifact loader. -/
theorem raw_bytes_cannot_call_artifact_loader :
    ∀ Γ spec payload,
      spec.inputKind = InputKind.artifact →
      ¬ ImportedDangerousCall Γ spec
        (Expr.app spec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ spec payload hkind hcall
  have htrusted : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) spec.inputKind.trustedTy :=
    imported_loader_input_must_be_trusted Γ spec (Expr.const (Value.vbytes payload)) hcall
  have hartifact : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) TyTrustedArtifact := by
    simpa [InputKind.trustedTy, hkind] using htrusted
  exact untrusted_bytes_not_typed_as_trusted_artifact Γ payload hartifact

/-- Raw bytes cannot call a binary-stream loader. -/
theorem raw_bytes_cannot_call_binary_io_loader :
    ∀ Γ spec payload,
      spec.inputKind = InputKind.binaryIO →
      ¬ ImportedDangerousCall Γ spec
        (Expr.app spec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ spec payload hkind hcall
  have htrusted : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) spec.inputKind.trustedTy :=
    imported_loader_input_must_be_trusted Γ spec (Expr.const (Value.vbytes payload)) hcall
  have hbinary : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) TyTrustedBinaryIO := by
    simpa [InputKind.trustedTy, hkind] using htrusted
  exact untrusted_bytes_not_typed_as_trusted_binary_io Γ payload hbinary

/-- Raw bytes cannot call a bytes loader unless they have first been promoted to `TrustedBytes`. -/
theorem raw_bytes_cannot_call_bytes_loader_without_promotion :
    ∀ Γ spec payload,
      spec.inputKind = InputKind.bytes →
      ¬ ImportedDangerousCall Γ spec
        (Expr.app spec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ spec payload hkind hcall
  have htrusted : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) spec.inputKind.trustedTy :=
    imported_loader_input_must_be_trusted Γ spec (Expr.const (Value.vbytes payload)) hcall
  have hbytes : TrustedInputTyped Γ (Expr.const (Value.vbytes payload)) TyTrustedBytes := by
    simpa [InputKind.trustedTy, hkind] using htrusted
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ payload hbytes

/-- The load-time-risk flag is metadata on the imported path and input kind, not the return type. -/
theorem load_time_risk_independent_of_return_type :
    ∀ (spec : ImportedLoaderSpec) (returnTy : Ty),
      ({ spec with returnTy := returnTy } : ImportedLoaderSpec).loadTimeRisk = spec.loadTimeRisk := by
  intro spec returnTy
  rfl

/-- Changing only the apparent return type preserves the spec's input classification. -/
theorem input_kind_independent_of_return_type :
    ∀ (spec : ImportedLoaderSpec) (returnTy : Ty),
      ({ spec with returnTy := returnTy } : ImportedLoaderSpec).inputKind = spec.inputKind := by
  intro spec returnTy
  rfl

def embedchainOpenAPIPathLoaderSpec : ImportedLoaderSpec where
  path := "embedchain.loaders.openapi.OpenAPILoader.load_data"
  inputKind := InputKind.path
  returnTy := Ty.concrete "Documents"
  loadTimeRisk := true

def horovodCloudpickleBytesLoaderSpec : ImportedLoaderSpec where
  path := "horovod.runner.common.util.codec.loads_base64"
  inputKind := InputKind.bytes
  returnTy := Ty.concrete "DecodedValue"
  loadTimeRisk := true

def joblibPathLoaderSpec : ImportedLoaderSpec where
  path := "joblib.load"
  inputKind := InputKind.path
  returnTy := Ty.concrete "Model"
  loadTimeRisk := true

def modelArtifactLoaderSpec : ImportedLoaderSpec where
  path := "artifact-registry.load_model"
  inputKind := InputKind.artifact
  returnTy := Ty.concrete "Model"
  loadTimeRisk := true

theorem no_raw_bytes_to_embedchain_openapi_path_loader :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ embedchainOpenAPIPathLoaderSpec
        (Expr.app embedchainOpenAPIPathLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_path_loader Γ embedchainOpenAPIPathLoaderSpec payload rfl

theorem no_raw_bytes_to_horovod_cloudpickle_bytes_loader :
    ∀ Γ payload,
      ¬ ImportedDangerousCall Γ horovodCloudpickleBytesLoaderSpec
        (Expr.app horovodCloudpickleBytesLoaderSpec.expr (Expr.const (Value.vbytes payload))) TyUnsafeAny := by
  intro Γ payload
  exact raw_bytes_cannot_call_bytes_loader_without_promotion Γ horovodCloudpickleBytesLoaderSpec payload rfl

theorem trusted_joblib_path_loader_returns_unsafe :
    ∀ Γ path,
      ImportedDangerousCall Γ joblibPathLoaderSpec
        (Expr.app joblibPathLoaderSpec.expr (trustedPathExpr path)) TyUnsafeAny := by
  intro Γ path
  exact trusted_imported_input_still_returns_unsafe Γ joblibPathLoaderSpec
    (trustedPathExpr path) (TrustedInputTyped.T_trusted_path Γ path)

theorem trusted_artifact_loader_returns_unsafe :
    ∀ Γ locator,
      ImportedDangerousCall Γ modelArtifactLoaderSpec
        (Expr.app modelArtifactLoaderSpec.expr (trustedArtifactExpr locator)) TyUnsafeAny := by
  intro Γ locator
  exact trusted_imported_input_still_returns_unsafe Γ modelArtifactLoaderSpec
    (trustedArtifactExpr locator) (TrustedInputTyped.T_trusted_artifact Γ locator)

end TaintedTypingFramework
