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

3. Add this test module:

```python
from typing import cast
import pickle
import numpy as np

payload = b"..."
unsafe = np.load("model.npy", allow_pickle=True)
x = pickle.loads(payload)
y = cast(dict, pickle.loads(payload))  # trust: launch-lab reason: inbound artifact boundary
```

4. Run strict type-check:

```bash
mypy --strict main.py
```

Expected:

- `pickle.loads(payload)` and `np.load(..., allow_pickle=True)` errors to `Unsafe[Any]`
- `cast` line is accepted only if policy allows the `launch-lab` tag

5. Add trust policy in a local `pyproject.toml`:

```toml
[tool.pickle_secure]
allow_tags = ["launch-lab"]
deny_tags = []
require_reason = ["launch-lab"]
unknown_tag = "error"
```

6. Run:

```bash
pickle-secure audit .
```

Expected: no violations for `# trust: launch-lab ...` and one violation if you remove the tag.

7. Repeat with `allow_pickle=False`:

```python
data = np.load("model.npy", allow_pickle=False)
```

Expected: no numpy cast requirement from checker for default/pure-safe path (with current stub policy).

8. Open a second module with `# trust: legacy-migration` and no reason text.

Expected: `pickle-secure audit .` reports missing-reason violation.

9. Optional: run with a strict profile bootstrap.

```bash
pickle-secure init --profile=strict --write-precommit
```

Check generated config and rerun mypy + audit to confirm gates are active.
