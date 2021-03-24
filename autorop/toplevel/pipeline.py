from autorop import PwnState, constants
from copy import copy
from pwn import log
from functools import reduce
from typing import Tuple


def pipeline(state: PwnState, *funcs: constants.TYPE_PIPE) -> PwnState:
    """Put ``PwnState`` through a sequential "pipeline" of functions.

    Execute ``funcs`` sequentially, with the output of each function serving as the
    input to the next function.

    The state is copied on every call, for future black magic caching reasons.
    This means that every function receives its own copy.

    Arguments:
        state: The ``PwnState`` to pass to the first function in ``funcs``.
        funcs: Functions which operate on the ``PwnState`` and return another ``PwnState``.

    Returns:
        The ``PwnState`` returned by the last function in ``funcs``.
    """

    def reducer(state: PwnState, func: Tuple[int, constants.TYPE_PIPE]) -> PwnState:
        log.debug(repr(state))
        log.info(f"Pipeline [{func[0]+1}/{len(funcs)}]: {func[1].__name__}")
        return func[1](copy(state))

    return reduce(reducer, enumerate(funcs), state)
