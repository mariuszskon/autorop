from autorop import PwnState


def open_target(state: PwnState) -> PwnState:
    """Open a fresh target.

    This closes the previous target connection and opens a new one using
    ``target_factory()``.

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
