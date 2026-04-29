"""Argparse entry point for pickle-secure CLI."""

import argparse
import sys
from importlib.metadata import version
from pathlib import Path

from .audit_cmd import audit
from .init_cmd import init


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="pickle-secure",
        description="Audit and configure pickle-stubs-secure cast-escape sites",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {version('pickle-stubs-secure')}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # init subcommand
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize pyproject.toml with stubs path and config skeleton",
    )
    init_parser.add_argument(
        "--path",
        type=Path,
        default=Path("pyproject.toml"),
        help="Path to pyproject.toml (default: pyproject.toml)",
    )
    init_parser.add_argument(
        "--profile",
        choices=["basic", "strict"],
        default="basic",
        help="Config profile: basic (default) or strict (hardened knobs)",
    )
    init_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print diff without writing",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing values (strict profile only)",
    )
    init_parser.add_argument(
        "--write-precommit",
        action="store_true",
        help="Generate .pre-commit-config.yaml template",
    )
    init_parser.add_argument(
        "--checker",
        choices=["mypy", "pyright", "ty"],
        help="Override checker detection (mypy/pyright/ty)",
    )

    # audit subcommand
    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit path for cast-escape sites and policy violations",
    )
    audit_parser.add_argument(
        "path",
        type=Path,
        help="Path to audit (file or directory)",
    )
    audit_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to pyproject.toml (default: ./pyproject.toml)",
    )
    audit_parser.add_argument(
        "--by-tag",
        action="store_true",
        help="Group results by tag",
    )
    audit_parser.add_argument(
        "--tag",
        type=str,
        default=None,
        help="Filter to single tag",
    )
    audit_parser.add_argument(
        "--untagged",
        action="store_true",
        help="Only show untagged cast sites",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "init":
        return init(
            pyproject_path=args.path,
            dry_run=args.dry_run,
            checker_override=args.checker,
            profile=args.profile,
            force=args.force,
            write_precommit=args.write_precommit,
        )

    if args.command == "audit":
        return audit(
            path=args.path,
            config_path=args.config,
            by_tag=args.by_tag,
            tag_filter=args.tag,
            untagged_only=args.untagged,
            json_output=args.json,
        )

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
