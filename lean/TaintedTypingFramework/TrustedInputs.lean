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
def TyUnsafeAny : Ty := Ty.unsafe_ (Ty.concrete "Any")

def trustedBytesValue (s : String) : Value :=
  Value.vconcrete "TrustedBytes" (Value.vbytes s)

def trustedPathValue (p : String) : Value :=
  Value.vconcrete "TrustedPath" (Value.vbytes p)

def trustedBytesExpr (s : String) : Expr := Expr.const (trustedBytesValue s)
def trustedPathExpr (p : String) : Expr := Expr.const (trustedPathValue p)

/-- The dangerous loader families modeled by the trusted-input extension. -/
inductive Loader : Type
  | pickle
  | cloudpickle
  | yaml
  | torch
  deriving Repr, DecidableEq

def Loader.inputTy : Loader → Ty
  | Loader.pickle => TyTrustedBytes
  | Loader.cloudpickle => TyTrustedBytes
  | Loader.yaml => TyTrustedPath
  | Loader.torch => TyTrustedPath

def Loader.name : Loader → String
  | Loader.pickle => "pickle"
  | Loader.cloudpickle => "cloudpickle"
  | Loader.yaml => "yaml"
  | Loader.torch => "torch"

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

end TaintedTypingFramework
