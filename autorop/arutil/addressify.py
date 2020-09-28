from autorop import PwnState
from pwn import context, unpack


def addressify(data: bytes) -> int:
    """Produce the address from a data leak."""
    result: int = unpack(data[: context.bits // 8].ljust(context.bits // 8, b"\x00"))
    return result
