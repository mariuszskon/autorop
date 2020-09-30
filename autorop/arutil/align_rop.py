from autorop import PwnState, arutil
from pwn import ROP, context, log


def align_rop(rop: ROP, n: int) -> ROP:
    """Pad ``rop`` to ``n`` words using ``ret`` instructions.

    Arguments:
        rop: The rop chain to pad.
        n: the minimum size of the rop chain after padding, in words.

    Returns:
        Reference to the mutated rop chain ``rop``, which is padded to be
        at least ``n`` bytes long.
    """
    log.debug("Padding rop chain to {} words".format(n))
    current_words: int = len(rop.chain()) // context.bytes
    return arutil.pad_rop(rop, n - current_words)
