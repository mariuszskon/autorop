from pwn import context, tube, ELF
from typing import Optional, Callable, Dict


class PwnState:
    """Class for keeping track of our exploit development."""

    def __init__(self, binary_name: str, target: tube, vuln_function: str = "main"):
        """Initialise the ``PwnState``.

        This initialises the state with the given parameters and default values.
        We also set ``context.binary`` to the given ``binary_name``,
        and ``context.cyclic_size`` to ``context.bytes``.

        Arguments:
            binary_name: Path to the binary to exploit
            target: What we want to exploit (can be local, or remote)
            vuln_function: Name of vulnerable function in binary,
                           which we can return to repeatedly
        """
        #: Path to the binary to exploit.
        self.binary_name: str = binary_name

        #: What we want to exploit (can be local, or remote).
        self.target: tube = target

        #: Name of vulnerable function in binary,
        #: which we can return to repeatedly.
        self.vuln_function: str = vuln_function

        #: pwntools ``ELF`` of ``binary_name``.
        self.elf: ELF = ELF(self.binary_name)

        #: ``ELF`` of ``target``'s libc.
        self.libc: Optional[ELF] = None

        #: Offset to return address via buffer overflow.
        self.bof_ret_offset: Optional[int] = None

        #: Function which writes rop chain to the "right place"
        #: (usually return address)
        #: e.g. it might be as simple as prepending some padding,
        #: or it might need to do format string attacks
        self.overwriter: Optional[Callable[[tube, bytes], None]] = None

        #: Leaked symbols of ``libc``.
        self.leaks: Dict[str, int] = {}

        # set pwntools' context appropriately
        context.binary = self.binary_name  # set architecture etc. automagically
        context.cyclic_size = context.bytes

    def __repr__(self) -> str:
        return f"<PwnState {str(vars(self))}>"
