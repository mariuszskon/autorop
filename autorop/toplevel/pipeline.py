from autorop import PwnState, constants
from pwn import log
from pwn import context
from functools import reduce
from typing import Callable, Tuple


def pipeline(state: PwnState, *funcs: constants.TYPE_PIPE) -> PwnState:
    """Put ``PwnState`` through a sequential "pipeline" of functions.

    Arguments:
        state: The ``PwnState`` to pass to the first function in ``funcs``.
        funcs: Functions which operate on the ``PwnState`` and return it.

    Returns:
        The ``PwnState`` returned by the last function in ``funcs``.
    """

    def reducer(state: PwnState, func: Tuple[int, constants.TYPE_PIPE]) -> PwnState:
        log.debug(repr(state))
        log.info(f"Pipeline [{func[0]+1}/{len(funcs)}]: {func[1].__name__}")
        return func[1](state)

    return reduce(reducer, enumerate(funcs), state)
