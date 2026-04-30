# Stub Symbol Manifest

This table lists every symbol mutated by pickle-stubs-secure.

| Module  | Qualname         | Stub Return | Hook Target (historical, unused in rev2) |
|---------|------------------|-------------|------------------------------------------|
| pickle  | loads            | Unsafe[Any] | get_function_hook("pickle.loads")        |
| pickle  | load             | Unsafe[Any] | get_function_hook("pickle.load")         |
| pickle  | Unpickler.load   | Unsafe[Any] | get_method_hook("pickle.Unpickler.load") |
| _pickle | loads            | Unsafe[Any] | get_function_hook("_pickle.loads")       |
| _pickle | load             | Unsafe[Any] | get_function_hook("_pickle.load")        |
| _pickle | Unpickler.load   | Unsafe[Any] | get_method_hook("_pickle.Unpickler.load")|
| numpy   | load             | Any or Unsafe[Any] | get_function_hook("numpy.load") (unsafe when allow_pickle=True) |
| langchain_community.vectorstores.faiss | FAISS.deserialize_from_bytes | Unsafe[Any] | CVE wrapper stub |
| langchain_community.vectorstores.faiss | FAISS.load_local | Unsafe[Any] | CVE wrapper stub |
| langchain.vectorstores.faiss | FAISS.deserialize_from_bytes | Unsafe[Any] | CVE wrapper stub |
| langchain.vectorstores.faiss | FAISS.load_local | Unsafe[Any] | CVE wrapper stub |
| kedro.io | ShelveStore reads | Unsafe[Any] | CVE wrapper stub |
| llama_index.core | JsonPickleSerializer loads/deserializes | Unsafe[Any] | CVE wrapper stub |
| pyfory | loads/deserialize/Fory methods | Unsafe[Any] | CVE wrapper stub |
| socketio | queue manager handlers | Unsafe[Any] | CVE wrapper stub |
| pipecat.serializers.livekit | LivekitFrameSerializer.deserialize | Unsafe[Any] | CVE wrapper stub |
| torch_musa.utils.compare_tool | compare utilities | Unsafe[Any] | CVE wrapper stub |
| torch | load | Unsafe[Any] | CVE wrapper stub |

## Architecture (rev2)

Rev2 architecture uses `cast(T, expr)` as escape hatch. No plugin hook. The audit CLI (`pickle_secure_cli/audit_cmd.py`) enumerates cast sites and enforces tag-based policy. The Hook Target column above is historical — kept for reference if a checker plugin is ever revived.

## Notes

- `pickle.loads` / `pickle.load` in typeshed re-export from `_pickle`.
  Our stubs override both independently so `from _pickle import loads` also errors.
- `_Unpickler.load` (pure-Python fallback) is also mutated in `pickle.pyi` for completeness.
- `dump`, `dumps`, `Pickler` — unchanged (serialize-only, safe).
- `pickletools`, `copyreg` — not in scope.
