"""Test falcon-secure init for mypy."""

from pathlib import Path

import pytest

from falcon_secure.cli.init_cmd import init
from falcon_secure.cli._config import read_toml


@pytest.fixture
def mypy_pyproject(tmp_path: Path) -> Path:
    """Create a minimal mypy-configured pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """\
[tool.mypy]
python_version = "3.11"
strict = true
"""
    )
    return pyproject


def test_init_mypy_adds_mypy_path(mypy_pyproject: Path) -> None:
    """Init should add mypy_path to [tool.mypy]."""
    assert init(mypy_pyproject) == 0
    toml_data = read_toml(mypy_pyproject)
    mypy_cfg = toml_data["tool"]["mypy"]
    assert "mypy_path" in mypy_cfg
    assert isinstance(mypy_cfg["mypy_path"], list)
    assert len(mypy_cfg["mypy_path"]) > 0
    assert any("stubs" in p for p in mypy_cfg["mypy_path"])


def test_init_mypy_adds_falcon_secure_config(mypy_pyproject: Path) -> None:
    """Init should add [tool.falcon_secure] skeleton."""
    assert init(mypy_pyproject) == 0
    toml_data = read_toml(mypy_pyproject)
    assert "falcon_secure" in toml_data["tool"]
    cfg = toml_data["tool"]["falcon_secure"]
    assert cfg["allow_tags"] == ["general", "test-fixture"]
    assert cfg["unknown_tag"] == "error"


def test_init_mypy_idempotent(mypy_pyproject: Path) -> None:
    """Running init twice should be idempotent."""
    assert init(mypy_pyproject) == 0
    toml_data_1 = read_toml(mypy_pyproject)
    mypy_path_1 = toml_data_1["tool"]["mypy"]["mypy_path"]

    # Second run
    assert init(mypy_pyproject) == 0
    toml_data_2 = read_toml(mypy_pyproject)
    mypy_path_2 = toml_data_2["tool"]["mypy"]["mypy_path"]

    assert mypy_path_1 == mypy_path_2


def test_init_mypy_dry_run(mypy_pyproject: Path) -> None:
    """Dry-run should not modify file."""
    assert init(mypy_pyproject, dry_run=True) == 0
    toml_data = read_toml(mypy_pyproject)
    # mypy_path should not be added
    assert "mypy_path" not in toml_data.get("tool", {}).get("mypy", {})


def test_init_missing_file() -> None:
    """Init should fail gracefully on missing pyproject.toml."""
    result = init(Path("/nonexistent/pyproject.toml"))
    assert result == 1


def test_init_no_checker(tmp_path: Path) -> None:
    """Init should fail if no checker is configured."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[build-system]\nrequires = []\n")
    result = init(pyproject)
    assert result == 1


def test_init_checker_override(mypy_pyproject: Path) -> None:
    """Init should accept --checker override."""
    assert init(mypy_pyproject, checker_override="mypy") == 0
    toml_data = read_toml(mypy_pyproject)
    assert "mypy_path" in toml_data["tool"]["mypy"]
