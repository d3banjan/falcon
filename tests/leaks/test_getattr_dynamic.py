"""Leak: getattr(pickle, "loads")(b) bypasses stub entirely.

xfail: dynamic attribute access is invisible to mypy. The return type
of getattr() is Any, so no Unsafe[Any] error appears.

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
import pickle

data = b""
# getattr returns Any — mypy cannot see through dynamic dispatch
fn = getattr(pickle, "loads")
result = fn(data)   # return type is Any — no Unsafe[Any] error
x: dict = result    # no error: result is Any
'''


@pytest.mark.xfail(
    reason=(
        "getattr(pickle, 'loads')(b) is a known soundness hole. "
        "mypy cannot track dynamic attribute access — getattr() returns Any. "
        "Inherent mypy limitation, not a stub design failure."
    ),
    strict=True,
)
def test_static_getattr_is_blocked(tmp_path: Path) -> None:
    """Assert mypy blocks getattr dispatch — expected to FAIL."""
    fixture = tmp_path / "getattr_dynamic.py"
    fixture.write_text(FIXTURE_CONTENT)
    rc, output = mypy_check(fixture)
    assert rc != 0 and "Unsafe" in output, (
        f"Expected mypy to catch getattr escape but got:\n{output}"
    )


def test_runtime_rce_still_real(tmp_path: Path) -> None:
    """Runtime proof: RCE executes regardless of static typing."""
    marker = tmp_path / "rce_marker.txt"
    payload = rce_via_reduce(str(marker))

    script = "\n".join([
        "import pickle",
        f"data = {payload!r}",
        "fn = getattr(pickle, 'loads')",
        "fn(data)",
    ])
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    assert marker.exists(), "RCE marker not created — payload failed to execute"
