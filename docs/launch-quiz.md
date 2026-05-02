---
layout: page
title: Launch Quiz
---

{% include research_status.html %}

This is a step-by-step validation you can run in a fresh project folder.

## Quiz

1. Install Falcon: `pip install pickle-stubs-secure` (current compatibility package name)
2. Create `pyproject.toml` with this content:

```toml
[tool.mypy]
strict = true
```

3. Wire the installed stubs and audit policy:

```bash
pickle-secure init --profile=strict
```

4. Add this test module:

```python
from typing import cast
import pickle
import numpy as np
from pickle_stubs_secure.trust import trusted_bytes

payload = b"..."
unsafe: dict[str, object] = np.load("model.npy", allow_pickle=True)
x: dict[str, object] = pickle.loads(payload)
reviewed_payload = trusted_bytes(payload, reason="launch lab artifact reviewed")
reviewed_unsafe = pickle.loads(reviewed_payload)
reviewed_value: dict[str, object] = reviewed_unsafe
y = cast(dict[str, object], reviewed_unsafe)  # trust: launch-lab reason: inbound artifact boundary
```

5. Run strict type-check:

```bash
mypy --strict main.py
```

Expected:

- `pickle.loads(payload)` errors because raw `bytes` are not `TrustedBytes`
- `pickle.loads(reviewed_payload)` is accepted at the call because it uses `trusted_bytes(...)`
- `reviewed_value` and `np.load(..., allow_pickle=True)` still produce `Unsafe[Any]`
- `pickle-secure audit` accepts the `cast` line only if policy allows the `launch-lab` tag

6. Edit the generated `[tool.pickle_secure]` policy in `pyproject.toml` to contain:

```toml
[tool.pickle_secure]
allow_tags = ["launch-lab"]
deny_tags = []
require_reason = ["launch-lab"]
unknown_tag = "error"
```

7. Run:

```bash
pickle-secure audit .
```

Expected: no violations for `# trust: launch-lab ...` and one violation if you remove the tag.

8. Repeat with `allow_pickle=False`:

```python
data = np.load("model.npy", allow_pickle=False)
```

Expected: no numpy cast requirement from checker for default/pure-safe path (with current stub policy).

9. Open a second module with `# trust: launch-lab` and no reason text.

Expected: `pickle-secure audit .` reports missing-reason violation.

10. Optional: regenerate pre-commit wiring.

```bash
pickle-secure init --profile=strict --write-precommit
```

Check generated config and rerun mypy + audit to confirm gates are active.
