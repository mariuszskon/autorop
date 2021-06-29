from autorop import PwnState, Pipe


class OpenTarget(Pipe):
    def __init__(self) -> None:
        """Open a fresh target.

        This pipe will close the previous target connection and open a new one using
        ``target_factory()``.
        """
        super().__init__(())

    def __call__(self, state: PwnState) -> PwnState:
        """Open a fresh target.

        Arguments:
            state: The state with the old (if any) ``target`` and factory for targets
            ``target_factory()``.

        Returns:
            The mutated ``PwnState`` with a fresh target connection open.
        """
        if state.target is not None:
            try:
                state.target.close()
            except:
                pass

        state.target = state.target_factory()

        return state
