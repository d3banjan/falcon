"""Implement `pickle-secure init` — update pyproject.toml with stubs path and profiles."""

import sys
from pathlib import Path

try:
    import tomlkit
    HAS_TOMLKIT = True
except ImportError:
    HAS_TOMLKIT = False

from ._config import detect_checker, read_toml


def resolve_stubs_dir() -> Path:
    """
    Resolve our installed stubs directory.
    Returns: absolute path to the stubs/ directory in the wheel.
    """
    import pickle_stubs_secure
    pkg_dir = Path(pickle_stubs_secure.__file__).parent
    return pkg_dir.parent / "stubs"


def _apply_strict_mypy_config(mypy_cfg: dict, force: bool) -> bool:
    """Apply strict mypy knobs. Return True if changed."""
    strict_knobs = {
        "disallow_any_explicit": True,
        "disallow_any_expr": True,
        "disallow_any_decorated": True,
        "disallow_any_generics": True,
        "disallow_subclassing_any": True,
        "warn_return_any": True,
        "warn_unused_ignores": True,
        "no_implicit_reexport": True,
    }
    changed = False
    for key, value in strict_knobs.items():
        if force or key not in mypy_cfg:
            if mypy_cfg.get(key) != value:
                mypy_cfg[key] = value
                changed = True
    return changed


def _apply_strict_pyright_config(pyright_cfg: dict, force: bool) -> bool:
    """Apply strict pyright knobs. Return True if changed."""
    strict_knobs = {
        "reportAny": "error",
        "reportExplicitAny": "error",
        "reportImplicitAny": "error",
        "reportUnnecessaryTypeIgnoreComment": "error",
    }
    changed = False
    for key, value in strict_knobs.items():
        if force or key not in pyright_cfg:
            if pyright_cfg.get(key) != value:
                pyright_cfg[key] = value
                changed = True
    return changed


def _apply_strict_ruff_config(tool_cfg: dict, force: bool) -> bool:
    """Apply strict ruff lint rules. Return True if changed."""
    if "ruff" not in tool_cfg:
        tool_cfg["ruff"] = {}
    ruff_cfg = tool_cfg["ruff"]

    if "lint" not in ruff_cfg:
        ruff_cfg["lint"] = {}
    lint_cfg = ruff_cfg["lint"]

    strict_rules = [
        "PGH003",   # blank type-ignore
        "S301",     # bandit pickle warning
        "S307",     # eval/exec
        "B009",     # getattr with constant
        "B010",     # setattr with constant
    ]

    changed = False
    if "extend-select" not in lint_cfg:
        lint_cfg["extend-select"] = strict_rules
        changed = True
    else:
        current = lint_cfg["extend-select"]
        if not isinstance(current, list):
            current = [current]
        for rule in strict_rules:
            if force or rule not in current:
                if rule not in current:
                    current.append(rule)
                    changed = True
        if changed:
            lint_cfg["extend-select"] = current

    return changed


def _apply_strict_pickle_secure_config(ps_cfg: dict, force: bool) -> bool:
    """Tighten [tool.pickle_secure]. Return True if changed."""
    strict_cfg = {
        "allow_tags": ["general"],
        "deny_tags": ["legacy-migration"],
        "require_reason": ["legacy-migration"],
        "unknown_tag": "error",
    }
    changed = False
    for key, value in strict_cfg.items():
        if force or key not in ps_cfg:
            if ps_cfg.get(key) != value:
                ps_cfg[key] = value
                changed = True
    return changed


def init(
    pyproject_path: Path,
    dry_run: bool = False,
    checker_override: str | None = None,
    profile: str = "basic",
    force: bool = False,
    write_precommit: bool = False,
) -> int:
    """
    Update pyproject.toml:
    1. Detect checker (mypy/pyright/ty).
    2. Add our stubs dir to checker config.
    3. Add [tool.pickle_secure] skeleton if missing.
    4. If profile='strict', apply strict knobs to mypy/pyright/ruff + tighten pickle_secure.
    5. If write_precommit, generate .pre-commit-config.yaml template.
    Idempotent: no-op if path already present (unless --force).

    Returns: 0 on success, 1 on error.
    """
    if not pyproject_path.exists():
        print(f"Error: {pyproject_path} not found", file=sys.stderr)
        return 1

    toml_data = read_toml(pyproject_path)

    try:
        checker = detect_checker(toml_data, checker_override)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    stubs_dir = resolve_stubs_dir()
    stubs_dir_str = str(stubs_dir)

    # Ensure tool section exists
    if "tool" not in toml_data:
        toml_data["tool"] = {}

    changed = False

    # Update checker config
    if checker == "mypy":
        if "mypy" not in toml_data["tool"]:
            toml_data["tool"]["mypy"] = {}
        mypy_cfg = toml_data["tool"]["mypy"]
        if "mypy_path" not in mypy_cfg:
            mypy_cfg["mypy_path"] = [stubs_dir_str]
            changed = True
        elif isinstance(mypy_cfg["mypy_path"], list):
            if stubs_dir_str not in mypy_cfg["mypy_path"]:
                mypy_cfg["mypy_path"].append(stubs_dir_str)
                changed = True
        print(f"Updated mypy_path: {stubs_dir_str}")

        if profile == "strict":
            if _apply_strict_mypy_config(mypy_cfg, force):
                changed = True
                print("Applied strict mypy knobs")

    elif checker == "pyright":
        if "pyright" not in toml_data["tool"]:
            toml_data["tool"]["pyright"] = {}
        pyright_cfg = toml_data["tool"]["pyright"]
        if "stubPath" not in pyright_cfg:
            pyright_cfg["stubPath"] = stubs_dir_str
            changed = True
        elif pyright_cfg["stubPath"] != stubs_dir_str:
            pyright_cfg["stubPath"] = stubs_dir_str
            changed = True
        print(f"Updated stubPath: {stubs_dir_str}")

        if profile == "strict":
            if _apply_strict_pyright_config(pyright_cfg, force):
                changed = True
                print("Applied strict pyright knobs")

    elif checker == "ty":
        print(f"ty checker detected. Stub path (for manual config): {stubs_dir_str}")

    if profile == "strict":
        if _apply_strict_ruff_config(toml_data["tool"], force):
            changed = True
            print("Applied strict ruff rules")

    if "pickle_secure" not in toml_data["tool"]:
        if profile == "basic":
            toml_data["tool"]["pickle_secure"] = {
                "allow_tags": ["general", "test-fixture"],
                "deny_tags": [],
                "require_reason": [],
                "unknown_tag": "error",
            }
        else:
            toml_data["tool"]["pickle_secure"] = {
                "allow_tags": ["general"],
                "deny_tags": ["legacy-migration"],
                "require_reason": ["legacy-migration"],
                "unknown_tag": "error",
            }
        changed = True
        print("Added [tool.pickle_secure] skeleton")
    elif profile == "strict":
        if _apply_strict_pickle_secure_config(toml_data["tool"]["pickle_secure"], force):
            changed = True
            print("Tightened [tool.pickle_secure] for strict profile")

    if not changed:
        print("No changes needed (idempotent)")
        return 0

    if dry_run:
        print("\n--- Dry-run: would write ---")
        if HAS_TOMLKIT:
            print(tomlkit.dumps(toml_data))
        else:
            print("(tomlkit not installed; showing parsed data)")
            import json
            print(json.dumps(toml_data, indent=2, default=str))
        return 0

    if not HAS_TOMLKIT:
        print("Error: tomlkit not installed. Install via: pip install tomlkit", file=sys.stderr)
        return 1

    with open(pyproject_path, "w") as f:
        f.write(tomlkit.dumps(toml_data))

    print(f"Wrote {pyproject_path}")

    if write_precommit:
        precommit_path = pyproject_path.parent / ".pre-commit-config.yaml"
        precommit_content = _generate_precommit_config(checker, profile)

        if precommit_path.exists():
            print(f"Overwrite existing {precommit_path}")
        else:
            print(f"Wrote {precommit_path}")
        with open(precommit_path, "w") as f:
            f.write(precommit_content)

    return 0


def _generate_precommit_config(checker: str, profile: str) -> str:
    """Generate .pre-commit-config.yaml content."""
    checker_hook = {
        "mypy": {
            "repo": "https://github.com/pre-commit/mirrors-mypy",
            "rev": "v1.13.0",
            "hooks": [
                {
                    "id": "mypy",
                    "additional_dependencies": ["types-all"],
                }
            ]
        },
        "pyright": {
            "repo": "https://github.com/ReubenLimius/action-pyright",
            "rev": "v1.15.1",
            "hooks": [
                {
                    "id": "pyright",
                }
            ]
        },
        "ty": None,
    }.get(checker)

    yaml_content = "# Generated by pickle-secure init\n"
    yaml_content += "repos:\n"

    if checker_hook:
        yaml_content += f"  - repo: {checker_hook['repo']}\n"
        yaml_content += f"    rev: {checker_hook['rev']}\n"
        yaml_content += "    hooks:\n"
        for hook in checker_hook['hooks']:
            yaml_content += f"      - id: {hook['id']}\n"
            if 'additional_dependencies' in hook:
                yaml_content += "        additional_dependencies:\n"
                for dep in hook['additional_dependencies']:
                    yaml_content += f"          - {dep}\n"

    yaml_content += "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
    yaml_content += "    rev: v0.1.6\n"
    yaml_content += "    hooks:\n"
    yaml_content += "      - id: ruff-check\n"

    yaml_content += "  - repo: local\n"
    yaml_content += "    hooks:\n"
    yaml_content += "      - id: pickle-secure-audit\n"
    yaml_content += "        name: pickle-secure audit\n"
    yaml_content += "        entry: pickle-secure audit .\n"
    yaml_content += "        language: system\n"
    yaml_content += "        pass_filenames: false\n"
    yaml_content += "        always_run: true\n"

    return yaml_content
