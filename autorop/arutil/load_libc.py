from autorop import PwnState
from pwn import ELF, ROP


def load_libc(state: PwnState) -> ELF:
    """Load the libc specified in the given state into a pwntools' ``ELF``.

    Arguments:
        state: The state, with the following set

            - ``libc``: Path to ``target``'s libc.
            - ``libc_base``: Base address of ``libc``, or ``None`` if unknown.

    Returns:
        Loaded ``ELF`` of the libc with attributes set as expected.
    """
    assert state.libc is not None
    elf = ELF(state.libc)
    if state.libc_base is not None:
        elf.address = state.libc_base
    return elf
