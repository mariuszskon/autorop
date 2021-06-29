from autorop import PwnState
from typing import Any, Iterable


class Pipe:
    def __init__(self, params: Iterable[Any]):
        """Create a "pipe" which operates on a ``PwnState``.

        Pipes are abstractions that perform a single logical "step"
        on a ``PwnState``, returning the modified ``PwnState``.

        Arguments:
            params: The initialisation parameters which describe this pipe.

        Returns:
            A pipe, which takes and returns a single ``PwnState``.
        """
        from autorop import arutil

        self.description = arutil.pretty_function(self.__class__.__name__, params)

    def __call__(self, state: PwnState) -> PwnState:
        return state

    def __repr__(self) -> str:
        return self.description
