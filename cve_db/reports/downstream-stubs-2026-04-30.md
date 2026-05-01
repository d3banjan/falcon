# Downstream Pickle CVE Stub Coverage

Date: 2026-04-30

This report maps the seeded pickle-backed third-party CVEs to surgical overlay stubs.

## Coverage verdicts

| CVE | Project | Public API surface | Stub verdict |
|---|---|---|---|
| CVE-2019-6446 | NumPy | `numpy.load(..., allow_pickle=True)` | **Stubbed** with conditional `Unsafe[Any]` overload. |
| CVE-2024-5998 | LangChain / langchain-community | `FAISS.deserialize_from_bytes`, `FAISS.load_local` | **Stubbed** in both legacy and community import paths. |
| CVE-2024-9701 | Kedro | `ShelveStore` `__getitem__`, `get`, `load` | **Stubbed** as wrapper over `shelve`-backed reads. |
| CVE-2025-3108 | LlamaIndex | `JsonPickleSerializer` `deserialize`, `load`, `loads` | **Stubbed** as pickle-fallback serializer surface. |
| CVE-2025-50472 | ModelScope / ms-swift | model metadata load | **Partial**. Direct `pickle.load` is already caught; public API path needs source confirmation before stubbing exact module path. |
| CVE-2025-61622 | Apache Fory / pyfory | pickle fallback deserialize/load functions | **Stubbed** at `pyfory.loads`, `pyfory.deserialize`, and `Fory` methods. |
| CVE-2025-61765 | python-socketio | queue manager internal emit/callback handlers | **Partial**. Stubbed internal manager handlers, but deployment trust of message queue remains out of type scope. |
| CVE-2025-62373 | Pipecat | `LivekitFrameSerializer.deserialize` | **Stubbed**. |
| CVE-2025-65213 | torch_musa | compare utilities | **Stubbed**. |
| CVE-2026-26215 | manga-image-translator | FastAPI endpoints calling `pickle.loads` | **Source-only**. No stable consumer API stub; direct source call is caught by Falcon's stdlib pickle overlay, auth/nonce weakness is out of scope. |

## Additional current NVD hits observed during implementation

These appeared in NVD search results and should be triaged into JSONL before claiming exhaustive coverage:

- CVE-2025-32434: PyTorch `torch.load` deserialization. Stubbed conservatively at `torch.load`.
- CVE-2025-14931: Hugging Face `smolagents` pickle parsing. Added a narrow placeholder `RemotePythonExecutor` stub pending exact API confirmation.
- CVE-2025-57622: Step-Video-T2V endpoints calling `pickle.loads`. Source-only unless a stable client/library API exists.
- CVE-2024-10190: Horovod `codec.loads_base64` delegates to `cloudpickle.loads`. Stubbed as a diagnostic wrapper, not a load-time prevention claim.
- CVE-2024-12029: InvokeAI model-loading helpers delegate to `torch.load`. Stubbed as diagnostic wrappers, not a load-time prevention claim.
- CVE-2025-24357: vLLM PyTorch weight iterators delegate to `torch.load`. Stubbed as diagnostic wrappers, not a load-time prevention claim.

## Fixture

`tests/fixtures/fix_cve_downstream_wrappers.py` exercises representative downstream wrappers:

- NumPy
- LangChain FAISS
- pyfory
- PyTorch
- vLLM
- InvokeAI
- Horovod
- Pipecat
- torch_musa

## Limits

These stubs block unsafe returned-value use. They do not prove that attacker-controlled bytes cannot reach deserialization. That stronger claim requires the future `TrustedBytes` / `TrustedPath` proof family.
