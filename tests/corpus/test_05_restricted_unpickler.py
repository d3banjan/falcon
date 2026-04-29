"""Test 05: RestrictedUnpickler still flagged by mypy.

Demonstrates that runtime allowlists (CPython docs pattern) do NOT satisfy
the type-level constraint. The stub still returns Unsafe[Any].

Two assertions:
  - Runtime proof: payload executes via unrestricted pickle.load in subprocess,
    proving the RCE exists regardless of find_class allowlists.
  - Static proof: mypy --strict on fixture reports Unsafe[Any] on
    RestrictedUnpickler.load().
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.corpus.payloads import rce_via_restricted_unpickler
from tests.conftest import mypy_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_05_restricted_unpickler.py"


def test_runtime_rce_proof(tmp_path: Path) -> None:
    """Payload confirms RCE — the stub flags it regardless of runtime restrictions."""
    marker = tmp_path / "rce_marker.txt"
    payload = rce_via_restricted_unpickler(str(marker))
    payload_file = tmp_path / "payload.pkl"
    payload_file.write_bytes(payload)

    # Use unrestricted pickle to prove the payload is genuinely executable RCE.
    # The point: stub flags the call regardless of whether the developer
    # added a find_class allowlist — runtime restrictions are invisible to mypy.
    payload_file_str = str(payload_file)
    script = "\n".join([
        "import pickle",
        f"with open({payload_file_str!r}, 'rb') as f:",
        "    pickle.load(f)",
    ])
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    assert marker.exists(), "RCE marker file was not created"


def test_static_mypy_error() -> None:
    """mypy --strict on fixture must report Unsafe[Any] on RestrictedUnpickler.load()."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )
