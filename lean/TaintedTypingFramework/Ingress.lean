import TaintedTypingFramework.Syntax
import TaintedTypingFramework.Types
import TaintedTypingFramework.TrustedInputs

/-!
# Ingress.lean — provenance for untrusted ingress sources

This module models direct bytes, paths, and remote artifacts coming from
network/RPC/queue/socket ingress. These values are intentionally separate from
`TrustedBytes` and `TrustedPath`, so a direct dangerous-loader call on ingress
cannot satisfy the trusted-input precondition.
-/

namespace TaintedTypingFramework

def TyUntrustedBytes : Ty := Ty.concrete "UntrustedBytes"
def TyUntrustedPath : Ty := Ty.concrete "UntrustedPath"
def TyUntrustedArtifact : Ty := Ty.concrete "UntrustedArtifact"

/-- Ingress families that receive data from outside the trust boundary. -/
inductive IngressSource : Type
  | network
  | rpc
  | queue
  | socket
  | remoteArtifact
  deriving Repr, DecidableEq

def IngressSource.name : IngressSource → String
  | IngressSource.network => "network"
  | IngressSource.rpc => "rpc"
  | IngressSource.queue => "queue"
  | IngressSource.socket => "socket"
  | IngressSource.remoteArtifact => "remoteArtifact"

def untrustedBytesValue (source : IngressSource) (payload : String) : Value :=
  Value.tainted
    (Value.vconcrete "IngressBytes"
      (Value.vconcrete source.name (Value.vbytes payload)))

def untrustedPathValue (source : IngressSource) (path : String) : Value :=
  Value.tainted
    (Value.vconcrete "IngressPath"
      (Value.vconcrete source.name (Value.vbytes path)))

def untrustedArtifactValue (source : IngressSource) (locator : String) : Value :=
  Value.tainted
    (Value.vconcrete "IngressArtifact"
      (Value.vconcrete source.name (Value.vbytes locator)))

def untrustedBytesExpr (source : IngressSource) (payload : String) : Expr :=
  Expr.const (untrustedBytesValue source payload)

def untrustedPathExpr (source : IngressSource) (path : String) : Expr :=
  Expr.const (untrustedPathValue source path)

def untrustedArtifactExpr (source : IngressSource) (locator : String) : Expr :=
  Expr.const (untrustedArtifactValue source locator)

def networkBytesExpr (payload : String) : Expr :=
  untrustedBytesExpr IngressSource.network payload

def rpcBytesExpr (payload : String) : Expr :=
  untrustedBytesExpr IngressSource.rpc payload

def queueBytesExpr (payload : String) : Expr :=
  untrustedBytesExpr IngressSource.queue payload

def socketBytesExpr (payload : String) : Expr :=
  untrustedBytesExpr IngressSource.socket payload

def remoteArtifactPathExpr (path : String) : Expr :=
  untrustedPathExpr IngressSource.remoteArtifact path

def remoteArtifactExpr (locator : String) : Expr :=
  untrustedArtifactExpr IngressSource.remoteArtifact locator

/-- Typing for values with explicit untrusted ingress provenance. -/
inductive IngressTyped : TypeEnv → Expr → Ty → Prop
  | T_network_bytes : ∀ Γ payload,
      IngressTyped Γ (networkBytesExpr payload) TyUntrustedBytes
  | T_rpc_bytes : ∀ Γ payload,
      IngressTyped Γ (rpcBytesExpr payload) TyUntrustedBytes
  | T_queue_bytes : ∀ Γ payload,
      IngressTyped Γ (queueBytesExpr payload) TyUntrustedBytes
  | T_socket_bytes : ∀ Γ payload,
      IngressTyped Γ (socketBytesExpr payload) TyUntrustedBytes
  | T_remote_artifact_path : ∀ Γ path,
      IngressTyped Γ (remoteArtifactPathExpr path) TyUntrustedPath
  | T_remote_artifact : ∀ Γ locator,
      IngressTyped Γ (remoteArtifactExpr locator) TyUntrustedArtifact

theorem network_bytes_typed_untrusted_bytes :
    ∀ Γ payload, IngressTyped Γ (networkBytesExpr payload) TyUntrustedBytes := by
  intro Γ payload
  exact IngressTyped.T_network_bytes Γ payload

theorem rpc_bytes_typed_untrusted_bytes :
    ∀ Γ payload, IngressTyped Γ (rpcBytesExpr payload) TyUntrustedBytes := by
  intro Γ payload
  exact IngressTyped.T_rpc_bytes Γ payload

theorem queue_bytes_typed_untrusted_bytes :
    ∀ Γ payload, IngressTyped Γ (queueBytesExpr payload) TyUntrustedBytes := by
  intro Γ payload
  exact IngressTyped.T_queue_bytes Γ payload

theorem socket_bytes_typed_untrusted_bytes :
    ∀ Γ payload, IngressTyped Γ (socketBytesExpr payload) TyUntrustedBytes := by
  intro Γ payload
  exact IngressTyped.T_socket_bytes Γ payload

theorem remote_artifact_path_typed_untrusted_path :
    ∀ Γ path, IngressTyped Γ (remoteArtifactPathExpr path) TyUntrustedPath := by
  intro Γ path
  exact IngressTyped.T_remote_artifact_path Γ path

theorem remote_artifact_typed_untrusted_artifact :
    ∀ Γ locator, IngressTyped Γ (remoteArtifactExpr locator) TyUntrustedArtifact := by
  intro Γ locator
  exact IngressTyped.T_remote_artifact Γ locator

theorem untrusted_ingress_bytes_not_trusted_bytes :
    ∀ Γ source payload,
      ¬ TrustedInputTyped Γ (untrustedBytesExpr source payload) TyTrustedBytes := by
  intro Γ source payload h
  cases h

theorem untrusted_ingress_bytes_not_trusted_path :
    ∀ Γ source payload,
      ¬ TrustedInputTyped Γ (untrustedBytesExpr source payload) TyTrustedPath := by
  intro Γ source payload h
  cases h

theorem untrusted_ingress_path_not_trusted_path :
    ∀ Γ source path,
      ¬ TrustedInputTyped Γ (untrustedPathExpr source path) TyTrustedPath := by
  intro Γ source path h
  cases h

theorem untrusted_remote_artifact_not_trusted_path :
    ∀ Γ locator,
      ¬ TrustedInputTyped Γ (remoteArtifactExpr locator) TyTrustedPath := by
  intro Γ locator h
  cases h

theorem no_network_bytes_to_pickle :
    ∀ Γ payload,
      ¬ TrustedDangerousCall Γ Loader.pickle
        (Expr.app Loader.pickle.expr (networkBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload h
  have hb : TrustedInputTyped Γ (networkBytesExpr payload) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.pickle (networkBytesExpr payload) h
  exact untrusted_ingress_bytes_not_trusted_bytes Γ IngressSource.network payload hb

theorem no_rpc_bytes_to_cloudpickle :
    ∀ Γ payload,
      ¬ TrustedDangerousCall Γ Loader.cloudpickle
        (Expr.app Loader.cloudpickle.expr (rpcBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload h
  have hb : TrustedInputTyped Γ (rpcBytesExpr payload) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.cloudpickle (rpcBytesExpr payload) h
  exact untrusted_ingress_bytes_not_trusted_bytes Γ IngressSource.rpc payload hb

theorem no_queue_bytes_to_marshal_loads :
    ∀ Γ payload,
      ¬ TrustedDangerousCall Γ Loader.marshalLoads
        (Expr.app Loader.marshalLoads.expr (queueBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload h
  have hb : TrustedInputTyped Γ (queueBytesExpr payload) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.marshalLoads (queueBytesExpr payload) h
  exact untrusted_ingress_bytes_not_trusted_bytes Γ IngressSource.queue payload hb

theorem no_socket_bytes_to_dill_loads :
    ∀ Γ payload,
      ¬ TrustedDangerousCall Γ Loader.dillLoads
        (Expr.app Loader.dillLoads.expr (socketBytesExpr payload)) TyUnsafeAny := by
  intro Γ payload h
  have hb : TrustedInputTyped Γ (socketBytesExpr payload) TyTrustedBytes :=
    loader_input_must_be_trusted Γ Loader.dillLoads (socketBytesExpr payload) h
  exact untrusted_ingress_bytes_not_trusted_bytes Γ IngressSource.socket payload hb

theorem no_remote_artifact_path_to_torch :
    ∀ Γ path,
      ¬ TrustedDangerousCall Γ Loader.torch
        (Expr.app Loader.torch.expr (remoteArtifactPathExpr path)) TyUnsafeAny := by
  intro Γ path h
  have hp : TrustedInputTyped Γ (remoteArtifactPathExpr path) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.torch (remoteArtifactPathExpr path) h
  exact untrusted_ingress_path_not_trusted_path Γ IngressSource.remoteArtifact path hp

theorem no_remote_artifact_to_joblib :
    ∀ Γ locator,
      ¬ TrustedDangerousCall Γ Loader.joblib
        (Expr.app Loader.joblib.expr (remoteArtifactExpr locator)) TyUnsafeAny := by
  intro Γ locator h
  have hp : TrustedInputTyped Γ (remoteArtifactExpr locator) TyTrustedPath :=
    loader_input_must_be_trusted Γ Loader.joblib (remoteArtifactExpr locator) h
  exact untrusted_remote_artifact_not_trusted_path Γ locator hp

end TaintedTypingFramework
