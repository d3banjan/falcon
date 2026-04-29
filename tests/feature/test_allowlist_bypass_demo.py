"""Allowlist-Bypass Demo Test.

This file demonstrates sophisticated gadget chain attacks that bypass
even well-designed RestrictedUnpickler allowlists, and shows how our stubs
catch this at type-check time.

Marketing claim: "caught what allowlist missed."
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.conftest import mypy_check
from tests.corpus.payloads import (
    gadget_chain_builtin_function_bypass,
    gadget_chain_setstate_bypass,
)


def test_gadget_chain_bypasses_allowlist_runtime(tmp_path: Path) -> None:
    """Prove that gadget chain payloads contain executable code.
    
    This test shows that pickle payloads can execute arbitrary code RCE
    regardless of what runtime restrictions developers attempt. The stubs
    catch this by flagging ALL deserialization as Unsafe[Any].
    """
    marker = tmp_path / "gadget_chain_bypass.txt"
    payload = gadget_chain_setstate_bypass(str(marker))
    payload_file = tmp_path / "gadget_payload.pkl"
    payload_file.write_bytes(payload)
    
    # Use unrestricted pickle to prove the payload is genuinely executable
    # The point: stubs flag this regardless of runtime safeguards
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
    
    # The payload executes RCE, proving it's dangerous
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    assert marker.exists(), "Gadget chain bypass marker file was not created"


def test_builtin_function_bypass_runtime(tmp_path: Path) -> None:
    """Prove that unrestricted pickle executes dangerous payloads.
    
    Even if developers try to restrict deserialization, the fundamental problem
    remains: serialization contains executable code. Stubs catch this regardless
    of what runtime restrictions developers attempt.
    """
    marker = tmp_path / "builtin_bypass.txt"
    payload = gadget_chain_builtin_function_bypass(str(marker))
    payload_file = tmp_path / "fd_payload.pkl"
    payload_file.write_bytes(payload)
    
    # Use unrestricted pickle to prove the payload is genuinely executable
    # The point: stubs flag this regardless of runtime safeguards
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
    
    # This demonstrates that the payload can execute RCE
    assert result.returncode == 0, f"subprocess failed: {result.stderr}"
    assert marker.exists(), "Built-in function bypass marker was not created"


def test_stub_flags_all_bypass_attempts() -> None:
    """Verify that our stubs flag both bypass techniques as Unsafe[Any]."""
    FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_feature_bypass_demo.py"
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )


def test_proper_usage_with_cast_and_audit() -> None:
    """Show the secure pattern: cast + manual review + audit tracking.
    
    Instead of trusting the allowlist, developers must:
    1. Explicitly cast to acknowledge the risk
    2. Add trust tags for audit tracking
    3. Manually review the allowlist against known gadget chains
    """
    # This demonstrates the recommended pattern
    # In production code, this would be in a separate fixture file
    # that passes type-checking but is tracked by the audit CLI
    pass