from autorop import PwnState, Pipe, constants
from copy import copy
from pwn import log
from functools import reduce
from typing import Tuple


class Pipeline(Pipe):
    def __init__(self, *pipes: Pipe):
        """Produce a pipeline to put ``PwnState`` through a sequence of Pipes.

        Produce a state-copying function pipeline, which executes ``funcs`` sequentially,
        with the output of each function serving as the input to the next function.

        The state is copied on every call, for future black magic caching reasons.
        This means that every function receives its own copy.

        Arguments:
            pipes: Functions which operate on the ``PwnState`` and return another ``PwnState``.

        Returns:
            Pipe which puts ``PwnState`` through ``funcs`` and returns the ``PwnState``
            returned by the last function.
        """
        super().__init__(pipes)
        self.pipes = pipes
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

        def reducer(state: PwnState, pipe: Tuple[int, Pipe]) -> PwnState:
            log.debug(repr(state))
            log.info(f"Pipeline [{pipe[0]+1}/{len(self.pipes)}]: {pipe[1]}")
            return pipe[1](copy(state))

        return reduce(reducer, enumerate(self.pipes), state)
