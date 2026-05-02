"""Test falcon-secure init --profile=strict idempotency."""

from pathlib import Path

from falcon_secure.cli.init_cmd import init


def test_init_strict_idempotent(tmp_path: Path) -> None:
    """Test init --profile=strict second run = no-op."""
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
    result1 = init(pyproject, dry_run=False, profile="strict")
    assert result1 == 0
    content1 = pyproject.read_text()

    # Second run should be idempotent (no changes)
    result2 = init(pyproject, dry_run=False, profile="strict")
    assert result2 == 0
    content2 = pyproject.read_text()

    # Content should be identical
    assert content1 == content2


def test_init_strict_already_has_knobs(tmp_path: Path) -> None:
    """Test init --profile=strict when knobs already present."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""\
[build-system]
requires = ["hatchling"]

[project]
name = "test"

[tool.mypy]
strict = true
disallow_any_explicit = true
warn_return_any = true

[tool.ruff.lint]
extend-select = ["PGH003"]

[tool.falcon_secure]
allow_tags = ["general"]
deny_tags = ["legacy-migration"]
""")

    # Run should be idempotent
    result = init(pyproject, dry_run=False, profile="strict")
    assert result == 0
    content = pyproject.read_text()

    # All strict knobs should still be present
    assert "disallow_any_explicit = true" in content
    assert "warn_return_any = true" in content
    assert "PGH003" in content
    assert 'allow_tags = ["general"]' in content
