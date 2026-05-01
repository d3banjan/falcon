import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Types

/-!
# TrustedInputs.lean — trusted input model for dangerous loaders

This module adds a focused proof family for load-time preconditions. It does
not replace the existing post-return quarantine theorem. Instead, it models the
next proof obligation from the CVE research report:

* dangerous loaders require trusted inputs at the call site;
* accepted dangerous-loader calls still return `Unsafe[Any]`;
* raw bytes are not accepted as `TrustedBytes` or `TrustedPath`.
-/

namespace TaintedTypingFramework

def TyTrustedBytes : Ty := Ty.concrete "TrustedBytes"
def TyTrustedPath : Ty := Ty.concrete "TrustedPath"
def TyTrustedArtifact : Ty := Ty.concrete "TrustedArtifact"
def TyUnsafeAny : Ty := Ty.unsafe_ (Ty.concrete "Any")

def trustedBytesValue (s : String) : Value :=
  Value.vconcrete "TrustedBytes" (Value.vbytes s)

def trustedPathValue (p : String) : Value :=
  Value.vconcrete "TrustedPath" (Value.vbytes p)

def trustedArtifactValue (locator : String) : Value :=
  Value.vconcrete "TrustedArtifact" (Value.vbytes locator)

def trustedBytesExpr (s : String) : Expr := Expr.const (trustedBytesValue s)
def trustedPathExpr (p : String) : Expr := Expr.const (trustedPathValue p)
def trustedArtifactExpr (locator : String) : Expr := Expr.const (trustedArtifactValue locator)

/-- The dangerous loader families modeled by the trusted-input extension. -/
inductive Loader : Type
  | pickle
  | cloudpickle
  | yaml
  | torch
  | dill
  | dillLoad
  | dillLoads
  | joblib
  | marshal
  | marshalLoad
  | marshalLoads
  | pandasReadPickle
  | skopsCardGetModel
  | embedchainOpenAPILoader
  | horovodCloudpickleCodec
  deriving Repr, DecidableEq

def Loader.inputTy : Loader → Ty
  | Loader.pickle => TyTrustedBytes
  | Loader.cloudpickle => TyTrustedBytes
  | Loader.yaml => TyTrustedPath
  | Loader.torch => TyTrustedPath
  | Loader.dill => TyTrustedBytes
  | Loader.dillLoad => TyTrustedPath
  | Loader.dillLoads => TyTrustedBytes
  | Loader.joblib => TyTrustedPath
  | Loader.marshal => TyTrustedBytes
  | Loader.marshalLoad => TyTrustedPath
  | Loader.marshalLoads => TyTrustedBytes
  | Loader.pandasReadPickle => TyTrustedPath
  | Loader.skopsCardGetModel => TyTrustedPath
  | Loader.embedchainOpenAPILoader => TyTrustedPath
  | Loader.horovodCloudpickleCodec => TyTrustedBytes

def Loader.name : Loader → String
  | Loader.pickle => "pickle"
  | Loader.cloudpickle => "cloudpickle"
  | Loader.yaml => "yaml"
  | Loader.torch => "torch"
  | Loader.dill => "dill"
  | Loader.dillLoad => "dillLoad"
  | Loader.dillLoads => "dillLoads"
  | Loader.joblib => "joblib"
  | Loader.marshal => "marshal"
  | Loader.marshalLoad => "marshalLoad"
  | Loader.marshalLoads => "marshalLoads"
  | Loader.pandasReadPickle => "pandasReadPickle"
  | Loader.skopsCardGetModel => "skopsCardGetModel"
  | Loader.embedchainOpenAPILoader => "embedchainOpenAPILoader"
  | Loader.horovodCloudpickleCodec => "horovodCloudpickleCodec"

def Loader.expr (loader : Loader) : Expr :=
  Expr.const (Value.vconcrete "unsafe-loader" (Value.vconcrete loader.name Value.vunit))

/-- Typing for trusted ingress values used by dangerous-loader preconditions. -/
inductive TrustedInputTyped : TypeEnv → Expr → Ty → Prop
  | T_unit : ∀ Γ, TrustedInputTyped Γ (Expr.const Value.vunit) Ty.unit
  | T_bytes : ∀ Γ s, TrustedInputTyped Γ (Expr.const (Value.vbytes s)) Ty.bytes
  | T_int : ∀ Γ n, TrustedInputTyped Γ (Expr.const (Value.vint n)) Ty.int
  | T_var : ∀ Γ x τ, List.lookup x Γ = some τ → TrustedInputTyped Γ (Expr.var x) τ
  | T_trusted_bytes : ∀ Γ s, TrustedInputTyped Γ (trustedBytesExpr s) TyTrustedBytes
  | T_trusted_path : ∀ Γ p, TrustedInputTyped Γ (trustedPathExpr p) TyTrustedPath
  | T_trusted_artifact : ∀ Γ locator,
      TrustedInputTyped Γ (trustedArtifactExpr locator) TyTrustedArtifact

/-- Dangerous-loader calls in the trusted-input extension.

The constructor encodes the precondition: each loader can only be called with
the trusted input type selected by `Loader.inputTy`, and all such calls still
return `Unsafe[Any]`.
-/
inductive TrustedDangerousCall : TypeEnv → Loader → Expr → Ty → Prop
  | call : ∀ {Γ loader arg},
      TrustedInputTyped Γ arg loader.inputTy →
      TrustedDangerousCall Γ loader (Expr.app loader.expr arg) TyUnsafeAny

/-- Raw bytes are not trusted bytes. -/
theorem untrusted_bytes_not_typed_as_trusted_bytes :
    ∀ Γ s, ¬ TrustedInputTyped Γ (Expr.const (Value.vbytes s)) TyTrustedBytes := by
  intro Γ s h
  cases h

/-- Raw bytes are not trusted paths. -/
theorem untrusted_bytes_not_typed_as_trusted_path :
    ∀ Γ s, ¬ TrustedInputTyped Γ (Expr.const (Value.vbytes s)) TyTrustedPath := by
  intro Γ s h
  cases h

/-- Raw bytes are not trusted artifacts. -/
theorem untrusted_bytes_not_typed_as_trusted_artifact :
    ∀ Γ s, ¬ TrustedInputTyped Γ (Expr.const (Value.vbytes s)) TyTrustedArtifact := by
  intro Γ s h
  cases h

/-- Dangerous loaders can only be called with their trusted input type. -/
theorem loader_input_must_be_trusted :
    ∀ Γ loader arg,
      TrustedDangerousCall Γ loader (Expr.app loader.expr arg) TyUnsafeAny →
      TrustedInputTyped Γ arg loader.inputTy := by
  intro Γ loader arg h
  cases h with
  | call harg => exact harg

/-- Raw bytes cannot flow into `pickle.loads` in well-typed trusted-loader calls. -/
theorem no_untrusted_bytes_to_pickle :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.pickle
      (Expr.app Loader.pickle.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.pickle (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Raw bytes cannot flow into `cloudpickle.loads` in well-typed trusted-loader calls. -/
theorem no_untrusted_bytes_to_cloudpickle :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.cloudpickle
      (Expr.app Loader.cloudpickle.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.cloudpickle (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Raw bytes cannot be used as trusted paths for `yaml.load`. -/
theorem no_untrusted_bytes_to_yaml :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.yaml
      (Expr.app Loader.yaml.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.yaml (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted paths for `torch.load`. -/
theorem no_untrusted_bytes_to_torch :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.torch
      (Expr.app Loader.torch.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.torch (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted bytes for `dill.loads`. -/
theorem no_untrusted_bytes_to_dill :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.dill
      (Expr.app Loader.dill.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.dill (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Raw bytes cannot be used as trusted paths for `dill.load`. -/
theorem no_untrusted_bytes_to_dill_load :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.dillLoad
      (Expr.app Loader.dillLoad.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.dillLoad (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted bytes for `dill.loads`. -/
theorem no_untrusted_bytes_to_dill_loads :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.dillLoads
      (Expr.app Loader.dillLoads.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.dillLoads (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Raw bytes cannot be used as trusted paths for `joblib.load`. -/
theorem no_untrusted_bytes_to_joblib :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.joblib
      (Expr.app Loader.joblib.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.joblib (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted bytes for `marshal`. -/
theorem no_untrusted_bytes_to_marshal :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.marshal
      (Expr.app Loader.marshal.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.marshal (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Raw bytes cannot be used as trusted paths for `marshal.load`. -/
theorem no_untrusted_bytes_to_marshal_load :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.marshalLoad
      (Expr.app Loader.marshalLoad.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.marshalLoad (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted bytes for `marshal.loads`. -/
theorem no_untrusted_bytes_to_marshal_loads :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.marshalLoads
      (Expr.app Loader.marshalLoads.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.marshalLoads (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Raw bytes cannot be used as trusted paths for `pandas.read_pickle`. -/
theorem no_untrusted_bytes_to_pandas_read_pickle :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.pandasReadPickle
      (Expr.app Loader.pandasReadPickle.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.pandasReadPickle (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted paths for `skops.Card.get_model`. -/
theorem no_untrusted_bytes_to_skops_card_get_model :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.skopsCardGetModel
      (Expr.app Loader.skopsCardGetModel.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.skopsCardGetModel (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted paths for `embedchain.OpenAPILoader.load_data`. -/
theorem no_untrusted_bytes_to_embedchain_openapi_loader :
    ∀ Γ p, ¬ TrustedDangerousCall Γ Loader.embedchainOpenAPILoader
      (Expr.app Loader.embedchainOpenAPILoader.expr (Expr.const (Value.vbytes p))) TyUnsafeAny := by
  intro Γ p h
  have hp : TrustedInputTyped Γ (Expr.const (Value.vbytes p)) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.embedchainOpenAPILoader (Expr.const (Value.vbytes p)) h
  exact untrusted_bytes_not_typed_as_trusted_path Γ p hp

/-- Raw bytes cannot be used as trusted bytes for `horovod.runner.common.util.codec.loads_base64`. -/
theorem no_untrusted_bytes_to_horovod_cloudpickle_codec :
    ∀ Γ b, ¬ TrustedDangerousCall Γ Loader.horovodCloudpickleCodec
      (Expr.app Loader.horovodCloudpickleCodec.expr (Expr.const (Value.vbytes b))) TyUnsafeAny := by
  intro Γ b h
  have hb : TrustedInputTyped Γ (Expr.const (Value.vbytes b)) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.horovodCloudpickleCodec (Expr.const (Value.vbytes b)) h
  exact untrusted_bytes_not_typed_as_trusted_bytes Γ b hb

/-- Trusted byte inputs permit pickle loads, but the result is still `Unsafe[Any]`. -/
theorem trusted_pickle_load_returns_unsafe :
    ∀ Γ s, TrustedDangerousCall Γ Loader.pickle
      (Expr.app Loader.pickle.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Trusted byte inputs permit cloudpickle loads, but the result is still `Unsafe[Any]`. -/
theorem trusted_cloudpickle_load_returns_unsafe :
    ∀ Γ s, TrustedDangerousCall Γ Loader.cloudpickle
      (Expr.app Loader.cloudpickle.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Trusted path inputs permit yaml.load, but the result is still `Unsafe[Any]`. -/
theorem trusted_yaml_load_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.yaml
      (Expr.app Loader.yaml.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted path inputs permit torch.load, but the result is still `Unsafe[Any]`. -/
theorem trusted_torch_load_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.torch
      (Expr.app Loader.torch.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted byte inputs permit dill.loads, but the result is still `Unsafe[Any]`. -/
theorem trusted_dill_loads_returns_unsafe :
    ∀ Γ s, TrustedDangerousCall Γ Loader.dillLoads
      (Expr.app Loader.dillLoads.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Trusted path inputs permit dill.load, and the result is still `Unsafe[Any]`. -/
theorem trusted_dill_load_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.dillLoad
      (Expr.app Loader.dillLoad.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted byte inputs permit dill, treated as a `loads`-style call in this model, returning `Unsafe[Any]`. -/
theorem trusted_dill_load_returns_unsafe_bytes_input :
    ∀ Γ s, TrustedDangerousCall Γ Loader.dill
      (Expr.app Loader.dill.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Trusted path inputs permit joblib.load, but the result is still `Unsafe[Any]`. -/
theorem trusted_joblib_load_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.joblib
      (Expr.app Loader.joblib.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted byte inputs permit marshal.loads, but the result is still `Unsafe[Any]`. -/
theorem trusted_marshal_loads_returns_unsafe :
    ∀ Γ s, TrustedDangerousCall Γ Loader.marshalLoads
      (Expr.app Loader.marshalLoads.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Trusted path inputs permit marshal.load, but the result is still `Unsafe[Any]`. -/
theorem trusted_marshal_load_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.marshalLoad
      (Expr.app Loader.marshalLoad.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted byte inputs permit marshal, treated as `loads` in this model, but the result is still `Unsafe[Any]`. -/
theorem trusted_marshal_returns_unsafe_bytes_input :
    ∀ Γ s, TrustedDangerousCall Γ Loader.marshal
      (Expr.app Loader.marshal.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Trusted path inputs permit pandas.read_pickle, but the result is still `Unsafe[Any]`. -/
theorem trusted_pandas_read_pickle_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.pandasReadPickle
      (Expr.app Loader.pandasReadPickle.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted path inputs permit skops.Card.get_model, but the result is still `Unsafe[Any]`. -/
theorem trusted_skops_card_get_model_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.skopsCardGetModel
      (Expr.app Loader.skopsCardGetModel.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted path inputs permit embedchain.OpenAPILoader.load_data, but the result is still `Unsafe[Any]`. -/
theorem trusted_embedchain_openapi_loader_returns_unsafe :
    ∀ Γ p, TrustedDangerousCall Γ Loader.embedchainOpenAPILoader
      (Expr.app Loader.embedchainOpenAPILoader.expr (trustedPathExpr p)) TyUnsafeAny := by
  intro Γ p
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_path Γ p)

/-- Trusted byte inputs permit horovod cloudpickle codec calls, but the result is still `Unsafe[Any]`. -/
theorem trusted_horovod_cloudpickle_codec_returns_unsafe :
    ∀ Γ s, TrustedDangerousCall Γ Loader.horovodCloudpickleCodec
      (Expr.app Loader.horovodCloudpickleCodec.expr (trustedBytesExpr s)) TyUnsafeAny := by
  intro Γ s
  exact TrustedDangerousCall.call (TrustedInputTyped.T_trusted_bytes Γ s)

end TaintedTypingFramework
