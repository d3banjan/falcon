"""Test 04: shelf.get(key) triggers Unsafe[Any].

Two assertions:
  - Runtime proof: Getting from shelf deserializes payload.
  - Static proof: mypy --strict on fixture reports Unsafe[Any] error.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.conftest import mypy_check
from tests.shelve.payloads import rce_simple_marker

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_shelve_04_get.py"


def test_runtime_rce_proof(tmp_path: Path) -> None:
    """Payload executes when using shelf.get()."""
    marker = tmp_path / "rce_marker.txt"
    db_path = tmp_path / "test.db"
    
    payload = rce_simple_marker(str(marker))
    
    script = (
        f"import shelve, pickle\n"
        f"shelf = shelve.open(r'{db_path}')\n"
        f"shelf['key'] = pickle.loads({payload!r})\n"
        f"shelf.close()\n"
        f"shelf = shelve.open(r'{db_path}')\n"
        f"_ = shelf.get('key')\n"
        f"shelf.close()\n"
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