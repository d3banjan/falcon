"""Leak: `x: Any = pickle.loads(b)` absorbs Unsafe[Any] silently.

xfail: mypy allows assigning anything to `Any`. This is an inherent
mypy/Any limitation.

Still includes runtime proof that RCE executes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.corpus.payloads import rce_via_reduce
from tests.conftest import mypy_check

FIXTURE_CONTENT = '''\
from typing import Any
import pickle

data = b""
# Any annotation absorbs Unsafe[Any] — no mypy error
x: Any = pickle.loads(data)
y: dict = x  # no error: x is Any, assignment to dict is allowed
'''


@pytest.mark.xfail(
    reason=(
        "x: Any = pickle.loads(b) is a known soundness hole. "
        "mypy silently accepts assigning Unsafe[Any] to Any-annotated variables. "
        "Inherent mypy limitation — Any is top type for assignments."
    ),
    strict=True,
)
def test_static_any_annotation_is_blocked(tmp_path: Path) -> None:
    """Assert mypy blocks Any-annotation escape — expected to FAIL."""
    fixture = tmp_path / "any_escape.py"
    fixture.write_text(FIXTURE_CONTENT)
    rc, output = mypy_check(fixture)
    assert rc != 0 and "Unsafe" in output, (
        f"Expected mypy to catch Any escape but got:\n{output}"
    )


def test_runtime_rce_still_real(tmp_path: Path) -> None:
    """Runtime proof: RCE executes regardless of static typing."""
    marker = tmp_path / "rce_marker.txt"
    payload = rce_via_reduce(str(marker))

    script = "\n".join([
        "import pickle",
        f"data = {payload!r}",
        "pickle.loads(data)",
    ])
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    assert marker.exists(), "RCE marker not created — payload failed to execute"
