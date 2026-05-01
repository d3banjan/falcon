from typing import Any, Generic, TypeVar, final

T = TypeVar("T")

@final
class Unsafe(Generic[T]):
    def __init__(self, value: Any) -> None: ...
    def unwrap(self) -> T: ...
