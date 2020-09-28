from autorop.PwnState import PwnState
from pwn import log
from pwn import context
from functools import reduce
from typing import Callable


def pipeline(state: PwnState, *funcs: Callable[[PwnState], PwnState]) -> PwnState:
    """Pass the PwnState through a "pipeline", sequentially executing each given function."""

    with log.progress("Pipeline") as progress:

        def reducer(state: PwnState, func: Callable[[PwnState], PwnState]) -> PwnState:
            log.debug(state)
            progress.status(func.__name__)
            return func(state)

        return reduce(reducer, funcs, state)
