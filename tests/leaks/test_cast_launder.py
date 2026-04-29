"""Leak: cast(dict, pickle.loads(b)) bypasses Unsafe[Any].

xfail: mypy allows cast() to override any type — this is an inherent
mypy limitation, not a stub design failure.

Still includes runtime proof: the RCE executes in subprocess.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.corpus.payloads import rce_via_reduce
from tests.conftest import mypy_check

FIXTURE_CONTENT = '''\
from typing import cast
import pickle

data = b""
# cast launders Unsafe[Any] to dict — mypy allows this
result = cast(dict, pickle.loads(data))
x: dict = result  # no error: cast washes the Unsafe
'''


@pytest.mark.xfail(
    reason=(
        "cast(dict, pickle.loads(b)) is a known soundness hole. "
        "mypy permits cast() to override any type without restriction. "
        "Inherent mypy limitation, not a stub design failure."
    ),
    strict=True,
)
def test_static_cast_is_blocked(tmp_path: Path) -> None:
    """Assert mypy blocks the cast — expected to FAIL (cast bypasses Unsafe)."""
    fixture = tmp_path / "cast_launder.py"
    fixture.write_text(FIXTURE_CONTENT)
    rc, output = mypy_check(fixture)
    # We want mypy to fail on this. But it won't — cast succeeds.
    assert rc != 0 and "Unsafe" in output, (
        f"Expected mypy to catch cast launder but got:\n{output}"
    )


def test_runtime_rce_still_real(tmp_path: Path) -> None:
    """Even via cast, the RCE payload executes — the leak is real, not theoretical."""
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
