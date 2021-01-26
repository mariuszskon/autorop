from autorop import PwnState, turnkey, pipeline, leak


def classic_printf(state: PwnState) -> PwnState:
    """Perform an attack against a non-PIE/non-ASLR buffer-overflowable binary.

    Perform a ret2libc attack on a non-PIE/non-ASLR target
    (at most one of these is fine, but not both), leaking with ``printf``.
    You can set ``state.elf.address`` yourself and it might work for PIE and ASLR.
    We use `libc-database <https://github.com/niklasb/libc-database>`_ to find the libc, and then spawn a shell on the target.

    Arguments:
        state: The current ``PwnState``.

    Returns:
        Reference to the mutated ``PwnState``.
    """
    return turnkey.classic(state, leak=leak.printf)
