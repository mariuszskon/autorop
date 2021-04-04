from autorop import PwnState, libc


def auto(state: PwnState) -> PwnState:
    """Acquire libc using configured service.

    We can programmatically find and download libc based on function address leaks
    (two or more preferred). This function sets ``state.libc``, including setting
    ``state.libc.address`` for ready-to-use address calculation.

    Arguments:
        state: The current ``PwnState`` with at least the following set

            - ``libc_getter``: What to use to get libc. This might have its
              own requirements for attributes set in ``state``.

    Returns:
        Mutated ``PwnState``, with updates from ``libc_getter``.
    """
    assert state.libc_getter is not None

    return state.libc_getter(state)
