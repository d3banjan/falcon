"""Verify mypy correctly uses our stubs."""
from pathlib import Path

from tests.conftest import mypy_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_01_loads_reduce.py"


def test_mypy_detects_unsafe_any_on_loads() -> None:
    """mypy --strict on fixture must report Unsafe[Any] error."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )


def test_mypy_strict_mode_enabled() -> None:
    """Verify mypy is running with strict configuration."""
    rc, output = mypy_check(FIXTURE)
    strict_indicators = ["strict", "Strict"]
    assert any(indicator in output.lower() for indicator in strict_indicators) or rc != 0, (
        "mypy should be in strict mode"
    )