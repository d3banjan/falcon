from typing import Any

from _unsafe import Unsafe


def compare_for_single_op(*args: Any, **kwargs: Any) -> Unsafe[Any]: ...
def nan_inf_track_for_single_op(*args: Any, **kwargs: Any) -> Unsafe[Any]: ...

