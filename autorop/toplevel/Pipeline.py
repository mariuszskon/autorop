from autorop import PwnState, constants
from copy import copy
from pwn import log
from functools import reduce
from typing import Tuple


class Pipeline:
    def __init__(self, *funcs: constants.TYPE_PIPE):
        """Produce a pipeline to put ``PwnState`` through a sequence of functions.

        Produce a state-copying function pipeline, which executes ``funcs`` sequentially,
        with the output of each function serving as the input to the next function.

        The state is copied on every call, for future black magic caching reasons.
        This means that every function receives its own copy.

        Arguments:
            funcs: Functions which operate on the ``PwnState`` and return another ``PwnState``.

        Returns:
            Function which puts ``PwnState`` through ``funcs`` and returns the ``PwnState``
            returned by the last function.
        """
        self.funcs = funcs
        log.info(f"Produced pipeline: {self}")

    def __call__(self, state: PwnState) -> PwnState:
        """Execute the pipeline.

        Execute the saved pipeline sequentially, making a copy of ``PwnState``
        before each function call.

        Arguments:
            state: The state to give to the first function.

        Returns:
            The state returned by the last function.
        """

        def reducer(state: PwnState, func: Tuple[int, constants.TYPE_PIPE]) -> PwnState:
            log.debug(repr(state))
            log.info(f"Pipeline [{func[0]+1}/{len(self.funcs)}]: {func[1]}")
            return func[1](copy(state))

        return reduce(reducer, enumerate(self.funcs), state)

    def __repr__(self) -> str:
        return f"pipeline_instance{self.funcs}"
