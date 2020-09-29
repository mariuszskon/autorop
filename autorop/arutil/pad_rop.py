from autorop import PwnState
from pwn import ROP


def pad_rop(rop: ROP, n: int) -> ROP:
    """Append `n` `ret` instructions to `rop`.

    Arguments:
        rop: The rop chain to pad.
        n: The number of `ret` instructions to pad `rop` with.

    Returns:
        Reference to mutated rop chain `rop`, which has had exactly `n` `ret`
        instructions appended to it.
    """
    for _ in range(n):
        rop.raw(rop.ret)
    return rop
