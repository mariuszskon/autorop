from autorop import PwnState
from pwn import context, unpack


def addressify(data: bytes) -> int:
    """Produce the address from a data leak.

    Arguments:
        data: Raw bytes that were leaked.

    Returns:
        The address which was part of the leak.
    """
    result: int = unpack(data[: context.bytes].ljust(context.bytes, b"\x00"))
    return result
