"""Verify the TrustedPath/TrustedBytes diagnostic across checkers."""

from pathlib import Path

from tests.conftest import mypy_check, pyright_check, ty_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_trusted_provenance.py"


def test_mypy_enforces_trusted_provenance() -> None:
    """mypy rejects raw inputs and still quarantines trusted-loader results."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert output.count("error:") >= 4, output
    assert "TrustedPath" in output, output
    assert "TrustedBytes" in output, output
    assert output.count("Unsafe[") >= 2, output


def test_pyright_enforces_trusted_provenance() -> None:
    """pyright rejects raw inputs and still quarantines trusted-loader results."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = pyright_check(FIXTURE)
    assert rc != 0, f"Expected pyright failure but got exit 0. Output:\n{output}"
    assert output.count("error:") >= 4, output
    assert "TrustedPath" in output, output
    assert "TrustedBytes" in output, output
    assert output.count("Unsafe[") >= 2, output


def test_ty_enforces_trusted_provenance() -> None:
    """ty rejects raw inputs and still quarantines trusted-loader results."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = ty_check(FIXTURE)
    assert rc != 0, f"Expected ty failure but got exit 0. Output:\n{output}"
    assert output.count("error[invalid-argument-type]") >= 2, output
    assert output.count("error[invalid-assignment]") >= 2, output
