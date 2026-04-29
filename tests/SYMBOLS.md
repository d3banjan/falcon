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

## Architecture (rev2)

Rev2 architecture uses `cast(T, expr)` as escape hatch. No plugin hook. The audit CLI (`pickle_secure_cli/audit_cmd.py`) enumerates cast sites and enforces tag-based policy. The Hook Target column above is historical — kept for reference if a checker plugin is ever revived.

## Notes

- `pickle.loads` / `pickle.load` in typeshed re-export from `_pickle`.
  Our stubs override both independently so `from _pickle import loads` also errors.
- `_Unpickler.load` (pure-Python fallback) is also mutated in `pickle.pyi` for completeness.
- `dump`, `dumps`, `Pickler` — unchanged (serialize-only, safe).
- `pickletools`, `copyreg` — not in scope.
