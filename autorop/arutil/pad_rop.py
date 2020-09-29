from autorop import PwnState
from pwn import ROP


def pad_rop(rop: ROP, n: int) -> ROP:
    """Pad `rop` with `n` `ret` instructions"""
    for _ in range(n):
        rop.raw(rop.ret)
    return rop
