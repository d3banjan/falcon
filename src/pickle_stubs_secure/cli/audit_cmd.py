"""Implement `pickle-secure audit` — enumerate and check unsafe escape sites."""

import ast
import json
import linecache
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from ._config import get_pickle_secure_config, read_toml


# Target deserialization functions: (module, name)
UNSAFE_PICKLE_FUNCS = {
    ("pickle", "loads"),
    ("pickle", "load"),
    ("_pickle", "loads"),
    ("_pickle", "load"),
    ("pickle", "Unpickler"),
    ("_pickle", "Unpickler"),
}

UNSAFE_NUMPY_FUNCS = {
    ("numpy", "load"),
}

UNSAFE_DOWNSTREAM_FUNCS = {
    ("pyfory", "loads"),
    ("pyfory", "deserialize"),
    ("torch", "load"),
    ("stepfun_ai", "call_remote_server"),
}

UNSAFE_DOWNSTREAM_METHODS = {
    "deserialize_from_bytes",
    "load_local",
    "deserialize_async",
    "compare_for_single_op",
    "nan_inf_track_for_single_op",
    "_handle_emit",
    "_handle_callback",
}

# Target shelve modules for unsafe read operations
UNSAFE_SHELF_MODULES = {
    "shelve",
}

TRUST_PROMOTION_FUNCS = {
    ("pickle_stubs_secure.trust", "trusted_path"): "trusted-path",
    ("pickle_stubs_secure.trust", "verify_path_sha256"): "trusted-path",
    ("pickle_stubs_secure.trust", "trusted_bytes"): "trusted-bytes",
    ("pickle_stubs_secure.trust", "verify_bytes_sha256"): "trusted-bytes",
    ("pickle_stubs_secure.trust", "trusted_binary_io"): "trusted-binary-io",
    ("pickle_stubs_secure.trust", "trusted_artifact"): "trusted-artifact",
}


class CastEscapeVisitor(ast.NodeVisitor):
    """AST visitor to find cast(T, pickle.loads(...)) patterns."""

    def __init__(self, filepath: str, source: str):
        self.filepath = filepath
        self.source = source
        self.casts: list[dict[str, Any]] = []
        self.import_aliases: dict[str, str] = {}  # {alias_name: real_module}
        self.from_imports: dict[str, tuple[str, str]] = {}

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track: from X import Y [as Z]."""
        if node.module:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                self.from_imports[name] = (node.module, alias.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track: import X [as Y]."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.import_aliases[name] = alias.name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Find cast(...) calls and check second arg."""
        if self._is_cast(node.func) and len(node.args) >= 2:
            second_arg = node.args[1]
            if (self._is_unsafe_pickle_call(second_arg) or 
                self._is_unsafe_shelve_operation(second_arg) or
                self._is_unsafe_shelve_subscript(second_arg) or
                self._is_unsafe_numpy_call(second_arg) or
                self._is_unsafe_downstream_call(second_arg)):
                self.casts.append(self._record_cast(node))
        self.generic_visit(node)

    def _is_unsafe_shelve_subscript(self, node: ast.expr) -> bool:
        """Check if node is shelf[key] subscript access."""
        if isinstance(node, ast.Subscript):
            return self._is_shelve_instance(node.value)
        return False

    def _is_true_flag(self, node: ast.expr) -> bool:
        """
        Interpret a Python bool expression for high-risk switches.
        Unknown values are treated as risky because they can be true.
        """
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        return True

    def _numpy_load_allows_pickle(self, node: ast.Call) -> bool:
        """
        Detect whether this np.load call can execute the pickling path.
        We treat explicit `allow_pickle=True` or unknown values as risky.
        """
        # Positional: np.load(file, mmap_mode, allow_pickle, ...)
        if len(node.args) >= 3:
            return self._is_true_flag(node.args[2])

        # Keyword form: np.load(file, allow_pickle=...)
        for kw in node.keywords:
            if kw.arg == "allow_pickle" and kw.value is not None:
                return self._is_true_flag(kw.value)

        # numpy defaults to allow_pickle=False
        return False

    def _is_unsafe_numpy_call(self, node: ast.expr) -> bool:
        """
        Check if node is a call to numpy.load with unsafe flags.
        """
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self.from_imports:
                mod, name = self.from_imports[func.id]
                if (mod, name) in UNSAFE_NUMPY_FUNCS:
                    return self._numpy_load_allows_pickle(node)
            return False

        if isinstance(func, ast.Attribute):
            if func.attr == "load":
                if isinstance(func.value, ast.Name):
                    module_name = func.value.id
                    if module_name in self.import_aliases:
                        module_name = self.import_aliases[module_name]
                    if (module_name, "load") in UNSAFE_NUMPY_FUNCS:
                        return self._numpy_load_allows_pickle(node)
        return False

    def _is_unsafe_downstream_call(self, node: ast.expr) -> bool:
        """
        Check for CVE-backed third-party wrapper APIs that delegate to pickle.
        This is intentionally name-shaped: the stubs enforce types; audit tracks casts.
        """
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self.from_imports:
                mod, name = self.from_imports[func.id]
                return (mod, name) in UNSAFE_DOWNSTREAM_FUNCS or name in UNSAFE_DOWNSTREAM_METHODS
            return func.id in UNSAFE_DOWNSTREAM_METHODS

        if isinstance(func, ast.Attribute):
            if func.attr in UNSAFE_DOWNSTREAM_METHODS:
                return True
            if isinstance(func.value, ast.Name):
                module_name = self.import_aliases.get(func.value.id, func.value.id)
                return (module_name, func.attr) in UNSAFE_DOWNSTREAM_FUNCS
        return False

    def _is_cast(self, node: ast.expr) -> bool:
        """Check if node resolves to typing.cast."""
        if isinstance(node, ast.Name):
            # Direct name: cast
            if node.id == "cast":
                return "cast" in self.from_imports or node.id == "cast"
            # Check from_imports
            if node.id in self.from_imports:
                mod, name = self.from_imports[node.id]
                return mod == "typing" and name == "cast"
        elif isinstance(node, ast.Attribute):
            # Attribute: typing.cast
            if node.attr == "cast":
                if isinstance(node.value, ast.Name):
                    if node.value.id == "typing":
                        return True
                    # Check import alias: typing as t → t.cast
                    if node.value.id in self.import_aliases:
                        return self.import_aliases[node.value.id] == "typing"
        return False

    def _is_unsafe_pickle_call(self, node: ast.expr) -> bool:
        """Check if node is a call to pickle.loads/load or Unpickler.load."""
        if not isinstance(node, ast.Call):
            return False

        func = node.func

        # Direct call: loads(...)
        if isinstance(func, ast.Name):
            if func.id in self.from_imports:
                mod, name = self.from_imports[func.id]
                return (mod, name) in UNSAFE_PICKLE_FUNCS
            # Might be from wildcard import; skip
            return False

        # Attribute call: pickle.loads, _pickle.load, Unpickler(...).load, etc.
        if isinstance(func, ast.Attribute):
            if func.attr in ("loads", "load"):
                if isinstance(func.value, ast.Name):
                    module_name = func.value.id
                    # Check if module_name is an alias
                    if module_name in self.import_aliases:
                        module_name = self.import_aliases[module_name]
                    return (module_name, func.attr) in UNSAFE_PICKLE_FUNCS

            # Handle Unpickler().load()
            if func.attr == "load":
                if isinstance(func.value, ast.Call):
                    # Unpickler(...).load()
                    inner_func = func.value.func
                    if isinstance(inner_func, ast.Name):
                        if inner_func.id in self.from_imports:
                            mod, name = self.from_imports[inner_func.id]
                            return (mod, name) in UNSAFE_PICKLE_FUNCS
                        # Direct Unpickler (might be imported)
                        if inner_func.id == "Unpickler":
                            return ("pickle", "Unpickler") in UNSAFE_PICKLE_FUNCS
                    elif isinstance(inner_func, ast.Attribute):
                        # pickle.Unpickler(...).load()
                        if isinstance(inner_func.value, ast.Name):
                            module_name = inner_func.value.id
                            if module_name in self.import_aliases:
                                module_name = self.import_aliases[module_name]
                            if inner_func.attr == "Unpickler":
                                return (module_name, "Unpickler") in UNSAFE_PICKLE_FUNCS
        return False

    def _is_unsafe_shelve_operation(self, node: ast.expr) -> bool:
        """Check if node is an unsafe shelve read operation (get, values, items)."""
        if not isinstance(node, ast.Call):
            return False

        func = node.func

        # Check for shelve.get(), shelve.values(), shelve.items()
        if isinstance(func, ast.Attribute):
            if func.attr in ("get", "values", "items"):
                # Check if the object is a Shelf instance
                # We check if the value is a Name, Attribute, or Call that might represent a Shelf
                return self._is_shelve_instance(func.value)

        return False

    def _is_shelve_instance(self, node: ast.expr) -> bool:
        """Check if node likely represents a shelve.Shelf instance."""
        if isinstance(node, ast.Name):
            # Direct variable: could be a Shelf instance
            # We can't be 100% certain without more sophisticated analysis,
            # but we conservatively assume any Name could be a Shelf
            return True
        elif isinstance(node, ast.Attribute):
            # Attribute access: might be shelve.open(...) result or similar
            return True
        elif isinstance(node, ast.Call):
            # Function call: shelve.open(...) returns a Shelf
            call_func = node.func
            if isinstance(call_func, ast.Attribute):
                if call_func.attr == "open":
                    if isinstance(call_func.value, ast.Name):
                        module_name = call_func.value.id
                        if module_name in self.import_aliases:
                            module_name = self.import_aliases[module_name]
                        return module_name in UNSAFE_SHELF_MODULES
        return False

    def _record_cast(self, node: ast.Call) -> dict[str, Any]:
        """Extract cast info: line number, tag, reason."""
        lineno = node.lineno
        line = linecache.getline(self.filepath, lineno).rstrip("\n")

        # Parse # trust: TAG [REASON]
        # TAG can be word characters or hyphens
        match = re.search(r"#\s*trust:\s*([\w-]+)(?:\s+(.+))?", line)
        tag = None
        reason = None
        if match:
            tag = match.group(1)  # will always match if pattern matches
            reason_text = match.group(2)
            if reason_text:
                reason = reason_text.strip()

        return {
            "file": self.filepath,
            "line": lineno,
            "code": line,
            "tag": tag,
            "reason": reason,
        }


class TrustPromotionVisitor(ast.NodeVisitor):
    """AST visitor to list explicit trusted-input promotion call sites."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.promotions: list[dict[str, Any]] = []
        self.import_aliases: dict[str, str] = {}
        self.from_imports: dict[str, tuple[str, str]] = {}

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track: from X import Y [as Z]."""
        if node.module:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                self.from_imports[name] = (node.module, alias.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Track: import X [as Y]."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.import_aliases[name] = alias.name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Find trusted_path/trusted_bytes/verified promotion calls."""
        promotion_kind = self._promotion_kind(node)
        if promotion_kind:
            self.promotions.append(self._record_promotion(node, promotion_kind))
        self.generic_visit(node)

    def _promotion_kind(self, node: ast.Call) -> str | None:
        func = node.func

        if isinstance(func, ast.Name):
            if func.id in self.from_imports:
                return TRUST_PROMOTION_FUNCS.get(self.from_imports[func.id])
            return None

        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                module_name = self.import_aliases.get(func.value.id, func.value.id)
                return TRUST_PROMOTION_FUNCS.get((module_name, func.attr))
        return None

    def _record_promotion(self, node: ast.Call, promotion_kind: str) -> dict[str, Any]:
        lineno = node.lineno
        line = linecache.getline(self.filepath, lineno).rstrip("\n")
        return {
            "type": "trust_promotion",
            "category": promotion_kind,
            "file": self.filepath,
            "line": lineno,
            "code": line,
            "message": f"explicit {promotion_kind} promotion",
        }


class SemanticPolicyVisitor(ast.NodeVisitor):
    """AST visitor for unsafe literal configuration that stubs cannot see."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[dict[str, Any]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for stmt in node.body:
            self._record_class_body_statement(stmt)
            self.visit(stmt)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        unsafe_keywords = self._unsafe_config_keywords(node)
        if unsafe_keywords:
            if self._is_super_init_call(node):
                self._record_finding(
                    node.lineno,
                    "super-init-unsafe-config",
                    f"super().__init__ forwards unsafe config: {', '.join(unsafe_keywords)}",
                )
            elif self._is_constructor_call(node):
                self._record_finding(
                    node.lineno,
                    "constructor-unsafe-config",
                    f"constructor call uses unsafe config: {', '.join(unsafe_keywords)}",
                )
        self.generic_visit(node)

    def _record_class_body_statement(self, stmt: ast.stmt) -> None:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                self._record_class_unsafe_assignment(target, stmt.value, stmt.lineno)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._record_class_unsafe_assignment(stmt.target, stmt.value, stmt.lineno)

    def _record_class_unsafe_assignment(
        self,
        target: ast.expr,
        value: ast.expr,
        lineno: int,
    ) -> None:
        if isinstance(target, ast.Name):
            if target.id == "safe" and self._is_false_literal(value):
                self._record_finding(lineno, "class-safe-false", "class config sets safe = False")
            elif target.id == "remote_exec" and self._is_true_literal(value):
                self._record_finding(
                    lineno,
                    "class-remote-exec-true",
                    "class config sets remote_exec = True",
                )

    def _unsafe_config_keywords(self, node: ast.Call) -> list[str]:
        unsafe_keywords = []
        for keyword in node.keywords:
            if keyword.arg == "safe" and self._is_false_literal(keyword.value):
                unsafe_keywords.append("safe=False")
            elif keyword.arg == "remote_exec" and self._is_true_literal(keyword.value):
                unsafe_keywords.append("remote_exec=True")
        return unsafe_keywords

    def _is_constructor_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name):
            return bool(func.id) and func.id[0].isupper()
        if isinstance(func, ast.Attribute):
            return bool(func.attr) and func.attr[0].isupper()
        return False

    def _is_super_init_call(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "__init__":
            return False
        value = func.value
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "super"
        )

    def _record_finding(self, lineno: int, rule: str, message: str) -> None:
        line = linecache.getline(self.filepath, lineno).rstrip("\n")
        self.findings.append(
            {
                "type": "unsafe_config",
                "category": "unsafe-config",
                "catchability": "checker-rule-needed",
                "rule": rule,
                "file": self.filepath,
                "line": lineno,
                "code": line,
                "message": message,
            }
        )

    def _is_true_literal(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    def _is_false_literal(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Constant) and node.value is False


def audit_file(filepath: Path) -> list[dict[str, Any]]:
    """AST-walk a single .py file, return list of cast escapes."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        print(f"Warning: syntax error in {filepath}: {e}", file=sys.stderr)
        return []

    visitor = CastEscapeVisitor(str(filepath), source)
    visitor.visit(tree)
    return visitor.casts


def audit_semantic_policy_file(filepath: Path) -> list[dict[str, Any]]:
    """AST-walk a single .py file, return unsafe semantic-policy findings."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        print(f"Warning: syntax error in {filepath}: {e}", file=sys.stderr)
        return []

    visitor = SemanticPolicyVisitor(str(filepath))
    visitor.visit(tree)
    return visitor.findings


def audit_trust_promotions_file(filepath: Path) -> list[dict[str, Any]]:
    """AST-walk a single .py file, return trusted-input promotion findings."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError as e:
        print(f"Warning: syntax error in {filepath}: {e}", file=sys.stderr)
        return []

    visitor = TrustPromotionVisitor(str(filepath))
    visitor.visit(tree)
    return visitor.promotions


def audit(
    path: Path,
    config_path: Path | None = None,
    by_tag: bool = False,
    tag_filter: str | None = None,
    untagged_only: bool = False,
    json_output: bool = False,
) -> int:
    """
    Audit path for cast-escape sites.
    Returns: 0 = no violations, 1 = violations found, 2 = parse error.
    """
    if not path.exists():
        print(f"Error: {path} not found", file=sys.stderr)
        return 2

    # Load config
    if config_path is None:
        config_path = Path("pyproject.toml")
    toml_data = read_toml(config_path)
    config = get_pickle_secure_config(toml_data)

    allow_tags = set(config.get("allow_tags", []))
    deny_tags = set(config.get("deny_tags", []))
    require_reason = set(config.get("require_reason", []))
    unknown_tag_mode = config.get("unknown_tag", "error")

    # Collect all cast escapes, trust promotions, and semantic-policy findings
    all_casts = []
    all_trust_promotions = []
    all_policy_findings = []
    py_files = list(path.rglob("*.py")) if path.is_dir() else [path]

    for pyfile in py_files:
        all_casts.extend(audit_file(pyfile))
        all_trust_promotions.extend(audit_trust_promotions_file(pyfile))
        all_policy_findings.extend(audit_semantic_policy_file(pyfile))

    # Filter
    if untagged_only:
        all_casts = [c for c in all_casts if c["tag"] is None]

    if tag_filter:
        all_casts = [c for c in all_casts if c["tag"] == tag_filter]

    # Validate against policy
    # Per call site, emit at most ONE violation (highest severity).
    # Priority: denied > unknown > missing-reason > untagged
    violations = []
    for cast_info in all_casts:
        tag = cast_info["tag"]
        reason = cast_info["reason"]
        violation_emitted = False

        # Check deny first (highest priority)
        if tag and tag in deny_tags:
            violations.append(
                {
                    "type": "denied_tag",
                    "file": cast_info["file"],
                    "line": cast_info["line"],
                    "tag": tag,
                    "message": f"denied tag: {tag}",
                }
            )
            violation_emitted = True
        # Check unknown tag (second priority)
        elif tag and tag not in allow_tags and unknown_tag_mode == "error":
            violations.append(
                {
                    "type": "unknown_tag",
                    "file": cast_info["file"],
                    "line": cast_info["line"],
                    "tag": tag,
                    "message": f"unknown tag: {tag}",
                }
            )
            violation_emitted = True
        # Check untagged (third priority, only if no tag)
        elif not tag and unknown_tag_mode == "error":
            violations.append(
                {
                    "type": "untagged",
                    "file": cast_info["file"],
                    "line": cast_info["line"],
                    "tag": None,
                    "message": "untagged cast escape",
                }
            )
            violation_emitted = True

        # Check require_reason (lowest priority, only if no other violation)
        if not violation_emitted and tag and tag in require_reason:
            if not reason:
                violations.append(
                    {
                        "type": "missing_reason",
                        "file": cast_info["file"],
                        "line": cast_info["line"],
                        "tag": tag,
                        "message": f"tag '{tag}' requires reason",
                    }
                )

    violations.extend(all_policy_findings)

    if json_output:
        output = {
            "total_casts": len(all_casts),
            "trust_promotions": all_trust_promotions,
            "semantic_findings": all_policy_findings,
            "violations": violations,
            "by_tag": _group_by_tag(all_casts) if not tag_filter else {},
        }
        print(json.dumps(output, indent=2))
        return 1 if violations else 0

    # Human output
    if by_tag:
        _print_by_tag(all_casts)
    else:
        _print_summary(all_casts, config)

    if all_policy_findings:
        print("\nSemantic policy findings:")
        for finding in all_policy_findings:
            print(
                f"  {finding['file']}:{finding['line']}: "
                f"{finding['category']} ({finding['catchability']}): {finding['message']}"
            )

    if all_trust_promotions:
        print("\nTrusted input promotions:")
        for promotion in all_trust_promotions:
            print(
                f"  {promotion['file']}:{promotion['line']}: "
                f"{promotion['category']}: {promotion['message']}"
            )

    if violations:
        print("\nViolations:")
        for v in violations:
            print(f"  {v['file']}:{v['line']}: {v['message']}")
        return 1

    return 0


def _group_by_tag(casts: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Group cast sites by tag."""
    by_tag = defaultdict(list)
    for cast_info in casts:
        tag = cast_info["tag"] or "<untagged>"
        by_tag[tag].append(f"{cast_info['file']}:{cast_info['line']}")
    return dict(by_tag)


def _print_by_tag(casts: list[dict[str, Any]]) -> None:
    """Print casts grouped by tag."""
    by_tag = _group_by_tag(casts)
    for tag in sorted(by_tag.keys()):
        sites = by_tag[tag]
        print(f"\n{tag}:")
        for site in sites:
            print(f"  {site}")


def _print_summary(casts: list[dict[str, Any]], config: dict[str, Any]) -> None:
    """Print summary of casts by tag with config hints."""
    by_tag = _group_by_tag(casts)
    allow_tags = set(config.get("allow_tags", []))
    deny_tags = set(config.get("deny_tags", []))
    require_reason = set(config.get("require_reason", []))

    print(f"\nTotal cast escapes: {len(casts)}\n")
    for tag in sorted(by_tag.keys()):
        sites = by_tag[tag]
        count = len(sites)

        status = []
        if tag == "<untagged>":
            status.append("[NEEDS REVIEW]")
        elif tag in deny_tags:
            status.append("[DENIED]")
        elif tag not in allow_tags:
            status.append("[UNKNOWN]")
        elif tag in require_reason:
            # Check if all have reasons
            tagged_casts = [c for c in casts if c["tag"] == tag]
            missing_reason = sum(1 for c in tagged_casts if not c["reason"])
            if missing_reason > 0:
                status.append(f"[{missing_reason} MISSING REASON]")

        status_str = " ".join(status) if status else ""
        print(f"  {tag:20s}: {count:3d} sites {status_str}")

    print("\nRun with --by-tag to see file:line locations")
