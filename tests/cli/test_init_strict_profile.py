"""Test falcon-secure init --profile=strict."""

from pathlib import Path

from falcon_secure.cli.init_cmd import init


def test_init_strict_profile(tmp_path: Path) -> None:
    """Test init --profile=strict applies strict knobs."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""\
[build-system]
requires = ["hatchling"]

[project]
name = "test"

[tool.mypy]
strict = true
""")

    result = init(pyproject, dry_run=False, profile="strict")
    assert result == 0

    # Read back and verify
    content = pyproject.read_text()

    # Check mypy strict knobs
    assert "disallow_any_explicit = true" in content
    assert "disallow_any_expr = true" in content
    assert "disallow_any_decorated = true" in content
    assert "disallow_any_generics = true" in content
    assert "disallow_subclassing_any = true" in content
    assert "warn_return_any = true" in content
    assert "warn_unused_ignores = true" in content
    assert "no_implicit_reexport = true" in content

    # Check ruff rules
    assert "PGH003" in content
    assert "S301" in content
    assert "S307" in content
    assert "B009" in content
    assert "B010" in content

    # Check falcon_secure tightened
    assert 'allow_tags = ["general"]' in content
    assert 'deny_tags = ["legacy-migration"]' in content
    assert 'require_reason = ["legacy-migration"]' in content


def test_init_strict_profile_pyright(tmp_path: Path) -> None:
    """Test init --profile=strict with pyright."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""\
[build-system]
requires = ["hatchling"]

[project]
name = "test"

[tool.pyright]
typeCheckingMode = "basic"
""")

    result = init(pyproject, dry_run=False, profile="strict", checker_override="pyright")
    assert result == 0

    content = pyproject.read_text()

    # Check pyright strict knobs
    assert 'reportAny = "error"' in content
    assert 'reportExplicitAny = "error"' in content
    assert 'reportImplicitAny = "error"' in content
    assert 'reportUnnecessaryTypeIgnoreComment = "error"' in content

    # Check ruff rules still present
    assert "PGH003" in content
