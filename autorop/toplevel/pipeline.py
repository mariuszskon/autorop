from autorop import PwnState
from pwn import log
from pwn import context
from functools import reduce
from typing import Callable


def pipeline(state: PwnState, *funcs: Callable[[PwnState], PwnState]) -> PwnState:
    """Put `PwnState` through a sequential "pipeline" of functions.

    Arguments:
        state: The `PwnState` to pass to the first function in `funcs`.
        funcs: Functions which operate on the `PwnState` and return it.

    Returns:
        The `PwnState` returned by the last function in `funcs`.
    """

    with log.progress("Pipeline") as progress:

        def reducer(state: PwnState, func: Callable[[PwnState], PwnState]) -> PwnState:
            log.debug(state)
            progress.status(func.__name__)
            return func(state)

        return reduce(reducer, funcs, state)
