from pwn import context, tube, ELF
from typing import Optional, Callable, Dict


class PwnState:
    """Class for keeping track of our exploit development."""

    def __init__(self, binary_name: str, target: tube, vuln_function: str = "main"):
        self.binary_name = binary_name  # path to binary
        self.target = target  # tube pointing to the victim to exploit
        self.vuln_function = vuln_function  # name of vulnerable function in binary,
        # to return to repeatedly
        self.elf: ELF = ELF(self.binary_name)  # pwntools ELF of binary_name
        self.libc: Optional[ELF] = None  # ELF of target's libc
        # offset to return address via buffer overflow
        self.bof_ret_offset: Optional[int] = None
        # function which write rop chain to the "right place" (usually return address)
        self.overwriter: Optional[Callable[[tube, bytes], None]] = None
        self.leaks: Dict[str, int] = {}  # leaked symbols

        # set pwntools' context appropriately
        context.binary = self.binary_name  # set architecture etc. automagically
        context.cyclic_size = context.bits / 8

    def __repr__(self) -> str:
        return f"<PwnState {str(vars(self))}>"
