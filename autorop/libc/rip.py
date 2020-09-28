from autorop import PwnState, arutil
from pwn import log, ELF, ROP
import requests
from typing import Dict


def rip(state: PwnState) -> PwnState:
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
    arutil.debug_requests(r)
    json = r.json()
    log.debug(json)
    if len(json) == 0:
        log.error("could not find any matching libc!")
    if len(json) > 1:
        log.warning(f"{len(json)} matching libc's found, picking first one")

    log.info("Downloading libc")
    r = requests.get(json[0]["download_url"])
    arutil.debug_requests(r)
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
