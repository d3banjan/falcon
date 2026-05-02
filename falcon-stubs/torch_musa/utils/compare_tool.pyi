from typing import Any

from _unsafe import Unsafe
from falcon_secure.trust import TrustedPath


def compare_for_single_op(
    inputs_data_save_path: TrustedPath,
    op_func: Any,
    atol: float,
    rtol: float,
    *args: Any,
    **kwargs: Any,
) -> Unsafe[Any]: ...
def nan_inf_track_for_single_op(
    inputs_data_save_path: TrustedPath,
    op_func: Any,
    *args: Any,
    **kwargs: Any,
) -> Unsafe[Any]: ...
