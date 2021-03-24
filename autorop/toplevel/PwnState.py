from pwn import context, tube, ELF, os
from copy import deepcopy
from typing import Optional, Callable, Dict, Any
from typing_extensions import Protocol
from dataclasses import dataclass, field


class OverwriterFunction(Protocol):
    def __call__(self, __t: tube, __data: bytes) -> Any:
        """Function which writes rop chain to the "right place"

        Function which writes rop chain to e.g. the return address.
        It might be as simple as prepending some padding, or it
        might need to do format string attacks.

        Arguments:
            __t: Where to write the data to.
            __data: The data to write at the "right place".

        Returns:
            Anything it likes, the result is ignored.
        """
        pass


def default_overwriter(t: tube, data: bytes) -> None:
    """Function which writes data via ``t.sendline(data)``"""
    t.sendline(data)


@dataclass
class PwnState:
    """Class for keeping track of our exploit development."""

    #: Path to the binary to exploit.
    binary_name: str

    #: What we want to exploit (can be local, or remote).
    target: tube

    #: Name of vulnerable function in binary,
    #: which we can return to repeatedly.
    vuln_function: str = "main"

    #: Path to local installation of libc-database, if using it.
    libc_database_path: str = os.path.expanduser("~/.libc-database")

    #: Path to ``target``'s libc.
    libc: Optional[str] = None

    #: Base address of ``target``'s libc.
    libc_base: Optional[int] = None

    #: Offset to return address via buffer overflow.
    bof_ret_offset: Optional[int] = None

    #: Function which writes rop chain to the "right place"
    overwriter: OverwriterFunction = default_overwriter

    #: Leaked symbols of ``libc``.
    leaks: Dict[str, int] = field(default_factory=dict)

    #: pwntools' ``ELF`` of ``binary_name``. Please only read from it.
    _elf: Optional[ELF] = None

    def __post_init__(self) -> None:
        """Initialise the ``PwnState``.

        This initialises the state with the given parameters and default values.
        We also set ``context.binary`` to the given ``binary_name``,
        and ``context.cyclic_size`` to ``context.bytes``.
        """
        if self._elf is None:
            object.__setattr__(self, "_elf", ELF(self.binary_name))

        # set pwntools' context appropriately
        context.binary = self.binary_name  # set architecture etc. automagically
        context.cyclic_size = context.bytes

    def __copy__(self) -> "PwnState":
        """Deep copy this state, except for ``target``..

        Perform a deep copy of the state, except for ``target`` (which remains
        a "constant pointer" to the target connection, which of course can change).
        ``_elf`` is also only shallow-copied but you should not be writing to it.
        """
        return PwnState(
            binary_name=self.binary_name,
            target=self.target,
            vuln_function=self.vuln_function,
            libc_database_path=self.libc_database_path,
            libc=self.libc,
            libc_base=self.libc_base,
            bof_ret_offset=self.bof_ret_offset,
            overwriter=self.overwriter,
            leaks=self.leaks.copy(),
            _elf=self._elf,
        )
