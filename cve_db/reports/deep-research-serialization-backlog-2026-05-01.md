# Deep Research Serialization Backlog — 2026-05-01

Source: distilled from local deep research report `deep-research-report (2).md`.

## Main Claim Audit

Falcon's current proof and checker model covers **post-return quarantine**:
dangerous deserialization APIs return `Unsafe[Any]`, and that value cannot flow
into trusted typed application code without an explicit reviewed escape.

It does **not** prove load-time RCE prevention. Many pickle, cloudpickle,
joblib, unsafe YAML, and torch loaders can execute attacker-controlled behavior
during the load operation before a meaningful value is returned.

Recommended wording:

> Falcon currently models post-return quarantine for values produced by
> dangerous deserializers and wrapper APIs. It does not yet prove safe invocation
> of those loaders on attacker-controlled bytes, files, sockets, queues, or
> model artifacts; published load-time RCE CVEs remain trusted-input work.

## Implement-Next Candidates

These are wrapper surfaces worth considering, but still require cautious
documentation because their advisories are primarily load-time issues.

| Package | Advisory | Candidate API | Sink | Falcon status |
|---|---|---|---|---|
| Embedchain | CVE-2024-23731 / GHSA-rhhj-5436-95vf | `embedchain.loaders.openapi.OpenAPILoader.load_data` | unsafe PyYAML | Candidate target stub plus `trusted-input-debt`. |
| lmdeploy | CVE-2025-67729 / GHSA-9pf3-7rrr-x5jh | `lmdeploy.vl.model.utils.load_weight_ckpt`, `lmdeploy.turbomind.deploy.loader.PytorchLoader.items` | `torch.load` | Low-priority candidate target stub; higher-priority `TrustedPath` target. |

## Keep Source-Only Or Trusted-Input-Boundary

These rows should not be counted as fully covered by return-type stubs.

| Package | Advisory | Reason |
|---|---|---|
| vLLM | CVE-2025-62164 / GHSA-mrw7-hf4f-83pf | Prompt-embedding path invokes `torch.load` on user-controlled bytes; vulnerability occurs at load/validation boundary. |
| vLLM | CVE-2025-24357 family | Model weight loading is a trusted artifact problem; source and sink-family evidence are useful, wrapper return stubs are secondary. |
| InvokeAI | CVE-2024-12029 / GHSA-g56c-68pp-6747 | Checkpoint probing/loading calls `torch.load`; prevention needs trusted model path policy. |
| Feast | CVE-2025-11157 / GHSA-34wm-4hw7-qfjv | Worker reads YAML config with unsafe loader; config provenance is the real boundary. |
| MONAI | CVE-2025-58756 / GHSA-6vm5-6jv9-rjpj | Checkpoint loading executes during deserialization; a return stub is not enough. |
| Transformers | CVE-2026-1839 / GHSA-69w3-r845-3855 | Trainer checkpoint resume calls `torch.load`; private flow is source-only for now. |
| Fugue | CVE-2025-62703 / GHSA-xv5p-fjw5-vrj6 | RPC server decodes with `cloudpickle.loads`; network trust dominates. |
| Horovod | CVE-2024-10190 family | Source evidence confirms `codec.loads_base64` reaches `cloudpickle.loads`; affected-version confirmation still needed. |

## Do Not Implement Now

| Row family | Reason |
|---|---|
| Picklescan/Fickling bypasses | Analyzer-policy advisories, not application source-to-sink flows. |
| Malicious-package records | Supply-chain malware, not a typed deserialization API contract. |
| PraisonAI workflow YAML execution | Workflow language intentionally executes commands; unsafe YAML loader stubs would be fake precision. |
| Broad smolagents target | Current source defaults away from pickle unless legacy `allow_pickle=True` is explicitly enabled. |
| Pipecat optional/deprecated serializer | Low-value optional internals; easy to overstate coverage. |
| Step-Video-T2V placeholder | Still lacks stable package/API confirmation. |

## Lean Impact

The current Lean model should remain scoped to post-return quarantine.

The first trusted-input extension is now represented by
`TaintedTypingFramework/TrustedInputs.lean`:

- dangerous loader calls are indexed by loader family;
- bytes loaders require `TrustedBytes`;
- path loaders require `TrustedPath`;
- accepted calls still return `Unsafe[Any]`;
- raw bytes are rejected by the trusted-input precondition theorem.

Remaining Lean backlog:

- model ingress provenance for network, RPC, queue, socket, and remote artifact
  sources;
- add explicit load-time vulnerability semantics, separate from returned-value
  taint;
- close the pre-existing `Soundness.lean` `sorry`s.
