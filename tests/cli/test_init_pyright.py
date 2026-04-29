"""Test pickle-secure init for pyright."""

from pathlib import Path

import pytest

from pickle_stubs_secure.cli.init_cmd import init
from pickle_stubs_secure.cli._config import read_toml


@pytest.fixture
def pyright_pyproject(tmp_path: Path) -> Path:
    """Create a minimal pyright-configured pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """\
[tool.pyright]
strict = true
"""
    )
    return pyproject


def test_init_pyright_adds_stubpath(pyright_pyproject: Path) -> None:
    """Init should add stubPath to [tool.pyright]."""
    assert init(pyright_pyproject) == 0
    toml_data = read_toml(pyright_pyproject)
    pyright_cfg = toml_data["tool"]["pyright"]
    assert "stubPath" in pyright_cfg
    assert "stubs" in pyright_cfg["stubPath"]


def test_init_pyright_adds_pickle_secure_config(pyright_pyproject: Path) -> None:
    """Init should add [tool.pickle_secure] skeleton."""
    assert init(pyright_pyproject) == 0
    toml_data = read_toml(pyright_pyproject)
    assert "pickle_secure" in toml_data["tool"]


def test_init_pyright_idempotent(pyright_pyproject: Path) -> None:
    """Running init twice should be idempotent."""
    assert init(pyright_pyproject) == 0
    toml_data_1 = read_toml(pyright_pyproject)
    stub_path_1 = toml_data_1["tool"]["pyright"]["stubPath"]

    # Second run
    assert init(pyright_pyproject) == 0
    toml_data_2 = read_toml(pyright_pyproject)
    stub_path_2 = toml_data_2["tool"]["pyright"]["stubPath"]

    assert stub_path_1 == stub_path_2
