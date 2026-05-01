"""Test fixtures for comparing security tools detection rates.

This module contains intentionally vulnerable code patterns to test security tools:
- Falcon stubs (type-based detection)
- Bandit (pattern-based AST analysis)
- Semgrep (pattern matching with custom rules)
- Ruff (linter-based detection)

Each pattern represents a different attack vector with varying difficulty for static tools.
"""

import pickle
import shelve
from typing import Any, Dict, Callable
from typing_extensions import cast


# Pattern 1: Direct pickle.loads (basic, should be caught by all tools)
def pattern_direct_loads(data: bytes) -> Any:
    """Direct deserialization - most basic attack pattern."""
    return pickle.loads(data)  # type: ignore[assignment]


# Pattern 2: Dynamic getattr dispatch (challenging for static tools)
def pattern_getattr_dispatch(data: bytes) -> Any:
    """Dynamic attribute access bypasses static analysis."""
    fn = getattr(pickle, "loads")
    return fn(data)


# Pattern 3: Cast laundering (stubs flag, other tools may miss)
def pattern_cast_launder(data: bytes) -> Dict[str, Any]:
    """Explicit cast bypasses type safety while creating audit trail."""
    return cast(Dict[str, Any], pickle.loads(data))


# Pattern 4: Shelve access (stubs flag, others likely miss)
def pattern_shelve_access(path: str, key: str) -> Any:
    """Shelve module deserialization - equivalent security risk to pickle."""
    with shelve.open(path) as db:
        return db[key]


# Pattern 5: Shelve get method (stubs flag, others likely miss)
def pattern_shelve_get(path: str, key: str) -> Any:
    """Shelve.get() method - unsafe deserialization through accessor method."""
    with shelve.open(path) as db:
        return db.get(key)


# Pattern 6: Shelve values iteration (stubs flag, others likely miss)
def pattern_shelve_values(path: str) -> list:
    """Shelve values() returns unsafe data in iteration."""
    with shelve.open(path) as db:
        return list(db.values())


# Pattern 7: Pickle load from file (basic, should be caught by all tools)
def pattern_file_load(file_path: str) -> Any:
    """File-based pickle deserialization - common pattern."""
    with open(file_path, "rb") as f:
        return pickle.load(f)


# Pattern 8: Unpickler class instantiation (medium complexity)
def pattern_unpickler_class(data: bytes) -> Any:
    """Unpickler class instantiation - object-oriented pattern."""
    unpickler = pickle.Unpickler(data)
    return unpickler.load()


# Pattern 9: Nested unsafe assignment (type system catches)
def pattern_nested_assignment(data: bytes) -> list:
    """Nested data structure with unsafe elements."""
    obj = pickle.loads(data)
    return [obj, "safe_string"]  # Unsafe[Any] cannot be used in list


# Pattern 10: Function parameter passing (type system catches)
def process_unsafe_data(data: bytes, handler: Callable) -> None:
    """Passing unsafe data to function parameters."""
    obj = pickle.loads(data)
    handler(obj)  # Unsafe[T] cannot be passed to expected type


# Pattern 11: Any annotation escape (soundness hole for stubs)
def pattern_any_annotation(data: bytes) -> Any:
    """Any annotation absorbs Unsafe type - known soundness hole."""
    x: Any = pickle.loads(data)
    return x  # No error, passes through Any


# Pattern 12: Dictionary assignment with unsafe value (type system catches)
def pattern_dict_assignment(data: bytes) -> Dict[str, Any]:
    """Assigning unsafe result to dictionary."""
    result: Dict[str, Any] = {}
    result["data"] = pickle.loads(data)  # Unsafe[Any] cannot be assigned
    return result


# Pattern 13: Conditional deserialization (complex control flow)
def pattern_conditional_deserialization(data: bytes, is_safe: bool) -> Any:
    """Conditional deserialization bypassing static analysis."""
    if is_safe:
        # Even with type narrowing, Unsafe remains
        return pickle.loads(data)
    return {}


# Pattern 14: Try-catch with unsafe operations
def pattern_try_catch_unsafe(data: bytes) -> Any:
    """Exception handling may obscure unsafe operations."""
    try:
        return pickle.loads(data)
    except Exception:
        # Still unsafe return type
        return None


# Pattern 15: List comprehension with unsafe elements
def pattern_list_comprehension(data_bytes_list: list) -> list:
    """List comprehension deserializing multiple payloads."""
    return [pickle.loads(data) for data in data_bytes_list]


# Pattern 16: Class attribute assignment
class UnsafeClass:
    """Class with unsafe attribute assignment."""
    def set_data(self, data: bytes) -> None:
        """Assigning unsafe data to class attribute."""
        self.safe_data: Dict[str, Any] = pickle.loads(data)


# Pattern 17: Type alias with unsafe
SafeConfig = Dict[str, Any]

def pattern_type_alias(data: bytes) -> SafeConfig:
    """Type alias does not bypass Unsafe typing."""
    return pickle.loads(data)  # Still Unsafe[Any]


# Pattern 18: Multiple assignments in one line
def pattern_multiple_assignments(data: bytes, data2: bytes) -> tuple:
    """Multiple unsafe assignments."""
    a = pickle.loads(data)
    b = pickle.loads(data2)
    return (a, b)  # Both Unsafe[Any]


# Pattern 19: Default parameter with unsafe
def pattern_default_param(data: bytes = b"safe") -> Any:
    """Default parameter doesn't make deserialization safe."""
    return pickle.loads(data)


# Pattern 20: Lambda with unsafe operation
def pattern_lambda_unsafe() -> callable:
    """Lambda function with unsafe deserialization."""
    return lambda data: pickle.loads(data)  # Returns Unsafe[Any]
