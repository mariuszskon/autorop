from autorop import PwnState, Pipe, constants, arutil
from pwn import log, ROP
from typing import List, Any


class Custom(Pipe):
    def __init__(self, func_name: str, args: List[Any] = [], align: bool = False):
        """Call an arbitrary function using rop chain.

        Call an arbitrary function using rop chain. This is basically a thin wrapper
        around using ROP in pwntools.

        Arguments:
            func_name: Symbol in executable which we can return to.
            args: Optional list of arguments to pass to function.
            align: Whether the call should be stack aligned or not.

        Returns:
            Function which takes a ``PwnState``, doing the call, and returns reference
            to the new ``PwnState``.
        """
        super().__init__((func_name, args, align))
        self.func_name = func_name
        self.args = args
        self.align = align

    def __call__(self, state: PwnState) -> PwnState:
        """Perform the call on the ``target`` in ``PwnState``.

        Arguments:
            state: The current ``PwnState``.

        Returns:
            The same ``PwnState``, but with the ``state.overwriter`` called
            with the generated rop chain.
        """

        rop = ROP(state._elf)

        if self.align:
            arutil.align_call(rop, self.func_name, self.args)
        else:
            rop.call(self.func_name, self.args)

        log.info(rop.dump())

        state.overwriter(state.target, rop.chain())

        return state
