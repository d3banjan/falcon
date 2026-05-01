# Deep Research Serialization Backlog — 2026-05-01

Source: distilled from local deep research reports, including the refreshed
`deep-research-report.md` received on 2026-05-01. The raw chat export is not
checked in because it contains tool-citation artifacts and broad working notes.

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

Public coverage wording should describe the 24 / 26 figure as source-or-sink
family classification coverage, not as prevention of the corresponding
load-time executions. The 16 / 26 implemented-stub figure should stay separate
from source-only rows, placeholders, and rows whose useful evidence is only a
route, file path, or internal helper.

## Implement-Next Candidates

These are wrapper surfaces worth considering, but still require cautious
documentation because their advisories are primarily load-time issues. The
refreshed report narrows this queue: Embedchain remains the strongest current
wrapper candidate and is now implemented; `lmdeploy` drops out of the high-confidence list; vLLM,
InvokeAI, and Horovod are promoted only as cautious diagnostic-wrapper targets.

| Package | Advisory | Candidate API | Sink | Falcon status |
|---|---|---|---|---|
| Embedchain | CVE-2024-23731 / GHSA-rhhj-5436-95vf | `embedchain.loaders.openapi.OpenAPILoader.load_data` | unsafe PyYAML | Implemented target stub plus `trusted-input-debt`. |
| vLLM | CVE-2025-24357 family | `vllm.model_executor.model_loader.weight_utils.pt_weights_iterator`, `multi_thread_pt_weights_iterator` | `torch.load` | Implemented diagnostic target stubs; not a prevention claim. |
| InvokeAI | CVE-2024-12029 / GHSA-g56c-68pp-6747 | `invokeai.backend.model_manager.model_on_disk.ModelOnDisk.load_state_dict`, `invokeai.app.services.model_load.model_load_default.ModelLoadService.load_model_from_path` | `torch.load` | Implemented diagnostic target stubs; prevention needs `TrustedPath`. |
| Horovod | CVE-2024-10190 family | `horovod.runner.common.util.codec.loads_base64`, reached via `ElasticRendezvousHandler._put_value` | `cloudpickle.loads` | Implemented diagnostic target stub; affected-version/source confirmation still matters. |

## Keep Source-Only Or Trusted-Input-Boundary

These rows should not be counted as fully covered by return-type stubs.

| Package | Advisory | Reason |
|---|---|---|
| vLLM | CVE-2025-62164 / GHSA-mrw7-hf4f-83pf | Prompt-embedding path invokes `torch.load` on user-controlled bytes; vulnerability occurs at load/validation boundary. |
| Feast | CVE-2025-11157 / GHSA-34wm-4hw7-qfjv | Worker reads YAML config with unsafe loader; config provenance is the real boundary. |
| MONAI | CVE-2025-58756 / GHSA-6vm5-6jv9-rjpj | Checkpoint loading executes during deserialization; a return stub is not enough. |
| Transformers | CVE-2026-1839 / GHSA-69w3-r845-3855 | Trainer checkpoint resume calls `torch.load`; private flow is source-only for now. |
| Fugue | CVE-2025-62703 / GHSA-xv5p-fjw5-vrj6 | Advisory names private `_decode` in `fugue/rpc/flask.py`, but current upstream source has moved away from that cloudpickle helper; keep source-only rather than overclaiming a current wrapper stub. |
| ai-flow | CVE-2024-0960 | Advisory names `ai_flow\cli\commands\workflow_command.py` and `cloudpickle.loads`, but the stable consumer API is not confirmed. |
| Upsonic | CVE-2025-6279 | Route-level evidence names `/tools/add_tool` and `cloudpickle.loads`; keep as needs-source-confirmation until a stable Python API is confirmed. |

## Do Not Implement Now

| Row family | Reason |
|---|---|
| Picklescan/Fickling bypasses | Analyzer-policy advisories, not application source-to-sink flows. |
| Malicious-package records | Supply-chain malware, not a typed deserialization API contract. |
| PraisonAI workflow YAML execution | Workflow language intentionally executes commands; unsafe YAML loader stubs would be fake precision. |
| Disputed joblib CVE-2024-34997 | Supplier-disputed trusted-cache behavior; keep out of denominator and do not use to pad joblib wrapper coverage. |
| Broad smolagents target | Current source defaults away from pickle unless legacy `allow_pickle=True` is explicitly enabled. |
| Pipecat optional/deprecated serializer | Low-value optional internals; easy to overstate coverage. |
| Step-Video-T2V placeholder | Still lacks stable package/API confirmation. |

The refreshed report also found no high-confidence new scikit-learn / joblib
wrapper advisory beyond the already-covered direct `joblib.load` and skops
model-card work. That gap should remain visible rather than being filled with
disputed or by-design joblib rows.

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
