from autorop import PwnState, constants, arutil
from pwn import log, ROP
from typing import List, Any


def custom(
    func_name: str, args: List[Any] = [], align: bool = False
) -> constants.TYPE_PIPE:
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

    def custom_call(state: PwnState) -> PwnState:
        rop = ROP(state._elf)

        if align:
            arutil.align_call(rop, func_name, args)
        else:
            rop.call(func_name, args)

        log.info(rop.dump())

        state.overwriter(state.target, rop.chain())

        return state

    return custom_call
