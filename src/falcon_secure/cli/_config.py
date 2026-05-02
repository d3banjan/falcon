"""Parse [tool.falcon_secure] and checker config from pyproject.toml."""

import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore


def read_toml(path: Path) -> dict[str, Any]:
    """Read pyproject.toml as dict."""
    if not path.exists():
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f)


def detect_checker(toml_data: dict[str, Any], checker_override: str | None = None) -> str:
    """
    Detect which checker is configured: mypy, pyright, or ty.
    Returns checker name or raises ValueError if none found.
    """
    if checker_override:
        if checker_override not in ("mypy", "pyright", "ty"):
            raise ValueError(f"Unknown checker: {checker_override}")
        return checker_override

    tool = toml_data.get("tool", {})
    if "mypy" in tool:
        return "mypy"
    if "pyright" in tool:
        return "pyright"
    if "ty" in tool:
        return "ty"

    raise ValueError(
        "No checker config found. Set [tool.mypy], [tool.pyright], or [tool.ty] in pyproject.toml, "
        "or use --checker"
    )


def get_falcon_secure_config(toml_data: dict[str, Any]) -> dict[str, Any]:
    """Extract [tool.falcon_secure] config, return defaults if absent."""
    config = toml_data.get("tool", {}).get("falcon_secure", {})
    defaults = {
        "allow_tags": ["general", "test-fixture"],
        "deny_tags": [],
        "require_reason": [],
        "unknown_tag": "error",
    }
    return {**defaults, **config}
