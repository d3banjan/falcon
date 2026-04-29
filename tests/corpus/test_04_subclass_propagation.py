"""Test 04: Unpickler subclass .load() inherits Unsafe[Any].

Two assertions:
  - Runtime proof: subprocess executes payload via subclass Unpickler.
  - Static proof: mypy --strict on fixture reports Unsafe[Any] error on subclass.load().
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.corpus.payloads import rce_via_subclass
from tests.conftest import mypy_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_04_subclass_propagation.py"


def test_runtime_rce_proof(tmp_path: Path) -> None:
    """Payload executes via Unpickler subclass in subprocess."""
    marker = tmp_path / "rce_marker.txt"
    payload = rce_via_subclass(str(marker))
    payload_file = tmp_path / "payload.pkl"
    payload_file.write_bytes(payload)

    script = (
        "import io, pickle\n"
        "class MyUnpickler(pickle.Unpickler):\n"
        "    def find_class(self, module, name):\n"
        "        return super().find_class(module, name)\n"
        f"with open({str(payload_file)!r}, 'rb') as f:\n"
        "    data = f.read()\n"
        "u = MyUnpickler(io.BytesIO(data))\n"
        "u.load()\n"
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
    """mypy --strict on fixture must report Unsafe[Any] on subclass.load()."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )
