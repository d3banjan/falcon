import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Types
import TaintedTypingFramework.TrustedInputs

/-!
# LoadTime.lean — load-time execution risk for dangerous loaders

This module keeps two facts distinct:

* a trusted-input precondition may allow a dangerous loader call;
* the returned value remains quarantined as `Unsafe[Any]`;
* some loader families still carry load-time execution risk before any
  returned value can be quarantined.
-/

namespace TaintedTypingFramework

/-- Loader families whose deserialization step may execute code at load time. -/
inductive LoadTimeRisk : Loader → Prop
  | pickle : LoadTimeRisk Loader.pickle
  | cloudpickle : LoadTimeRisk Loader.cloudpickle
  | yaml : LoadTimeRisk Loader.yaml
  | torch : LoadTimeRisk Loader.torch
  | dill : LoadTimeRisk Loader.dill
  | dillLoad : LoadTimeRisk Loader.dillLoad
  | dillLoads : LoadTimeRisk Loader.dillLoads
  | joblib : LoadTimeRisk Loader.joblib
  | marshal : LoadTimeRisk Loader.marshal
  | marshalLoad : LoadTimeRisk Loader.marshalLoad
  | marshalLoads : LoadTimeRisk Loader.marshalLoads
  | pandasReadPickle : LoadTimeRisk Loader.pandasReadPickle
  | skopsCardGetModel : LoadTimeRisk Loader.skopsCardGetModel
  | embedchainOpenAPILoader : LoadTimeRisk Loader.embedchainOpenAPILoader
  | horovodCloudpickleCodec : LoadTimeRisk Loader.horovodCloudpickleCodec

/-- A trusted call site whose loader may execute before the return value exists. -/
inductive LoadTimeRiskAt : TypeEnv → Loader → Expr → Prop
  | call : ∀ {Γ loader arg},
      LoadTimeRisk loader →
      TrustedInputTyped Γ arg loader.inputTy →
      LoadTimeRiskAt Γ loader (Expr.app loader.expr arg)

/-- Trusted input admits a dangerous call, but the return type is still `Unsafe[Any]`. -/
theorem trusted_input_does_not_erase_returned_unsafe :
    ∀ {Γ loader call τ},
      TrustedDangerousCall Γ loader call τ →
      τ = TyUnsafeAny := by
  intro Γ loader call τ h
  cases h
  rfl

/-- Load-time risk is classified from the loader family, not from the return type. -/
theorem load_time_risk_classification_separate_from_return_type :
    ∀ {Γ loader e},
      LoadTimeRiskAt Γ loader e →
      LoadTimeRisk loader := by
  intro Γ loader e h
  cases h with
  | call risk _ => exact risk

/-- Load-time-risk calls still have the usual returned-value quarantine. -/
theorem load_time_risk_call_returns_unsafe_any :
    ∀ {Γ loader arg},
      LoadTimeRiskAt Γ loader (Expr.app loader.expr arg) →
      TrustedDangerousCall Γ loader (Expr.app loader.expr arg) TyUnsafeAny := by
  intro Γ loader arg h
  cases h with
  | call _ trustedArg => exact TrustedDangerousCall.call trustedArg

/-- Example: a trusted pickle input can still have load-time risk. -/
theorem trusted_pickle_load_has_load_time_risk :
    ∀ Γ s,
      LoadTimeRiskAt Γ Loader.pickle
        (Expr.app Loader.pickle.expr (trustedBytesExpr s)) := by
  intro Γ s
  exact LoadTimeRiskAt.call LoadTimeRisk.pickle (TrustedInputTyped.T_trusted_bytes Γ s)

/-- Example: a trusted Embedchain OpenAPI config path can still have load-time YAML risk. -/
theorem trusted_embedchain_openapi_load_has_load_time_risk :
    ∀ Γ p,
      LoadTimeRiskAt Γ Loader.embedchainOpenAPILoader
        (Expr.app Loader.embedchainOpenAPILoader.expr (trustedPathExpr p)) := by
  intro Γ p
  exact LoadTimeRiskAt.call LoadTimeRisk.embedchainOpenAPILoader
    (TrustedInputTyped.T_trusted_path Γ p)

/-- Example: a trusted Horovod payload can still have cloudpickle load-time risk. -/
theorem trusted_horovod_codec_load_has_load_time_risk :
    ∀ Γ s,
      LoadTimeRiskAt Γ Loader.horovodCloudpickleCodec
        (Expr.app Loader.horovodCloudpickleCodec.expr (trustedBytesExpr s)) := by
  intro Γ s
  exact LoadTimeRiskAt.call LoadTimeRisk.horovodCloudpickleCodec
    (TrustedInputTyped.T_trusted_bytes Γ s)

end TaintedTypingFramework
