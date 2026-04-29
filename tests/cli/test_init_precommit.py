"""Test pickle-secure init --write-precommit."""

from pathlib import Path

from pickle_stubs_secure.cli.init_cmd import init


def test_init_precommit_creates_yaml(tmp_path: Path) -> None:
    """Test init --write-precommit creates .pre-commit-config.yaml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""\
[build-system]
requires = ["hatchling"]

[project]
name = "test"

[tool.mypy]
strict = true
""")

    result = init(pyproject, dry_run=False, write_precommit=True)
    assert result == 0

    precommit_yaml = tmp_path / ".pre-commit-config.yaml"
    assert precommit_yaml.exists()

    content = precommit_yaml.read_text()

    # Check key components
    assert "repos:" in content
    assert "mypy" in content
    assert "ruff" in content
    assert "pickle-secure-audit" in content
    assert "pickle-secure audit" in content


def test_init_precommit_idempotent(tmp_path: Path) -> None:
    """Test init --write-precommit idempotent."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""\
[build-system]
requires = ["hatchling"]

[project]
name = "test"

[tool.mypy]
strict = true
""")

    # First run
    result1 = init(pyproject, dry_run=False, write_precommit=True)
    assert result1 == 0
    precommit_yaml = tmp_path / ".pre-commit-config.yaml"
    content1 = precommit_yaml.read_text()

    # Second run
    result2 = init(pyproject, dry_run=False, write_precommit=True)
    assert result2 == 0
    content2 = precommit_yaml.read_text()

    # Content should be identical (idempotent)
    assert content1 == content2


def test_init_precommit_with_pyright(tmp_path: Path) -> None:
    """Test init --write-precommit with pyright."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""\
[build-system]
requires = ["hatchling"]

[project]
name = "test"

[tool.pyright]
typeCheckingMode = "basic"
""")

    result = init(
        pyproject,
        dry_run=False,
        write_precommit=True,
        checker_override="pyright",
    )
    assert result == 0

    precommit_yaml = tmp_path / ".pre-commit-config.yaml"
    content = precommit_yaml.read_text()

    # Check pyright hook is present
    assert "pyright" in content
    assert "ruff" in content
    assert "pickle-secure-audit" in content
