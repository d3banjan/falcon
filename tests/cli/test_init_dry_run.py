"""Test falcon-secure init --dry-run."""

from pathlib import Path

import pytest

from falcon_secure.cli.init_cmd import init
from falcon_secure.cli._config import read_toml


@pytest.fixture
def mypy_pyproject(tmp_path: Path) -> Path:
    """Create a minimal mypy-configured pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    original = """\
[tool.mypy]
python_version = "3.11"
strict = true
"""
    pyproject.write_text(original)
    return pyproject


def test_init_dry_run_no_changes(mypy_pyproject: Path) -> None:
    """Dry-run should not modify file."""
    original_content = mypy_pyproject.read_text()
    assert init(mypy_pyproject, dry_run=True) == 0
    assert mypy_pyproject.read_text() == original_content


def test_init_dry_run_vs_write(mypy_pyproject: Path, tmp_path: Path) -> None:
    """Dry-run output should match what write would do."""
    # Run with dry-run
    assert init(mypy_pyproject, dry_run=True) == 0
    dry_run_content = mypy_pyproject.read_text()

    # Prepare another file for real write
    pyproject_2 = tmp_path / "pyproject2.toml"
    pyproject_2.write_text(dry_run_content)

    # Run without dry-run
    assert init(pyproject_2, dry_run=False) == 0

    # File should be modified in second case
    assert pyproject_2.read_text() != dry_run_content
    # But should have mypy_path now
    toml_2 = read_toml(pyproject_2)
    assert "mypy_path" in toml_2["tool"]["mypy"]
