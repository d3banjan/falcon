"""Ensure both checkers agree on all cases."""
from pathlib import Path

from tests.conftest import mypy_check, pyright_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_01_loads_reduce.py"


def test_both_checkers_detect_unsafe_any() -> None:
    """Both mypy and pyright must detect Unsafe[Any] error."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    
    mypy_rc, mypy_output = mypy_check(FIXTURE)
    pyright_rc, pyright_output = pyright_check(FIXTURE)
    
    assert mypy_rc != 0, f"mypy should fail but got exit 0. Output:\n{mypy_output}"
    assert pyright_rc != 0, f"pyright should fail but got exit 0. Output:\n{pyright_output}"
    assert "Unsafe[Any]" in mypy_output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{mypy_output}"
    )
    assert "Unsafe[Any]" in pyright_output, (
        f"Expected 'Unsafe[Any]' in pyright output but got:\n{pyright_output}"
    )


def test_checker_consistency() -> None:
    """Verify both checkers produce consistent error patterns."""
    mypy_rc, mypy_output = mypy_check(FIXTURE)
    pyright_rc, pyright_output = pyright_check(FIXTURE)
    
    mypy_fails = mypy_rc != 0
    pyright_fails = pyright_rc != 0
    
    assert mypy_fails == pyright_fails, (
        f"Checkers disagree on pass/fail: mypy={'fail' if mypy_fails else 'pass'}, "
        f"pyright={'fail' if pyright_fails else 'pass'}"
    )
    
    if mypy_fails and pyright_fails:
        mypy_has_unsafe = "Unsafe" in mypy_output
        pyright_has_unsafe = "Unsafe" in pyright_output
        assert mypy_has_unsafe == pyright_has_unsafe, (
            "Checkers disagree on Unsafe detection"
        )