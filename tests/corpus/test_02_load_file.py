"""Test 02: pickle.load(file) path.

Two assertions:
  - Runtime proof: subprocess executes payload via pickle.load(file).
  - Static proof: mypy --strict on fixture reports Unsafe[Any] error.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


from tests.corpus.payloads import rce_via_load_file
from tests.conftest import mypy_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_02_load_file.py"


def test_runtime_rce_proof(tmp_path: Path) -> None:
    """Payload executes in subprocess, proves RCE via pickle.load(file)."""
    marker = tmp_path / "rce_marker.txt"
    payload = rce_via_load_file(str(marker))
    payload_file = tmp_path / "payload.pkl"
    payload_file.write_bytes(payload)

    script = (
        "import pickle\n"
        f"with open({str(payload_file)!r}, 'rb') as f:\n"
        "    pickle.load(f)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    assert marker.exists(), "RCE marker file was not created — payload did not execute"


def test_static_mypy_error() -> None:
    """mypy --strict on fixture must report Unsafe[Any] error."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )
