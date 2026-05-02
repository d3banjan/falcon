from typing import Generic, TypeVar, final

T = TypeVar("T")

@final
class Unsafe(Generic[T]):
    """Wrapper for values returned by deserialization APIs.

    An Unsafe[T] is NOT assignable to T without calling .unwrap().
    Phase 1b plugin will allow suppression via # trust-me comments.
    """

    def unwrap(self) -> T: ...
