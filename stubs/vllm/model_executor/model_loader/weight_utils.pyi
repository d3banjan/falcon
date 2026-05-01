from collections.abc import Iterator
from typing import Any

from _unsafe import Unsafe


def pt_weights_iterator(*args: Any, **kwargs: Any) -> Iterator[Unsafe[Any]]: ...
def multi_thread_pt_weights_iterator(*args: Any, **kwargs: Any) -> Iterator[Unsafe[Any]]: ...
