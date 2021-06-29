from autorop import PwnState, Pipe, libc


class Auto(Pipe):
    def __init__(self) -> None:
        """Acquire libc using configured service.

        We can programmatically find and download libc based on function address leaks
        (two or more preferred). This pipe will set ``state.libc``, including setting
        ``state.libc.address`` for ready-to-use address calculation.
        """
        super().__init__(())

    def __call__(self, state: PwnState) -> PwnState:
        """Perform the libc acquisition using ``state.libc_getter``.

        Arguments:
            state: The current ``PwnState`` with at least the following set

                - ``libc_getter``: What to use to get libc. This might have its
                  own requirements for attributes set in ``state``.

        Returns:
            Mutated ``PwnState``, with updates from ``libc_getter``.
        """
        assert state.libc_getter is not None

        return state.libc_getter(state)
