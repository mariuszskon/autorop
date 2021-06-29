from autorop import PwnState, Pipe, arutil
from pwn import log, ELF
import requests
from typing import Dict


class Rip(Pipe):
    def __init__(self) -> None:
        """Acquire libc version using https://libc.rip.

        We can programmatically find and download libc based on function address leaks
        (two or more preferred). This pipe will set ``state.libc``, including setting
        ``state.libc.address`` for ready-to-use address calculation.
        """
        super().__init__(())

    def __call__(self, state: PwnState) -> PwnState:
        """Acquire libc version using https://libc.rip.

        We can programmatically find and download libc based on function address leaks
        (two or more preferred). This function sets ``state.libc``, including setting
        ``state.libc.address`` for ready-to-use address calculation.

        Arguments:
            state: The current ``PwnState`` with the following set

                - ``leaks``: Leaked symbols of libc.

        Returns:
            Mutated ``PwnState``, with the following updated

                - ``libc``: Path to ``target``'s libc, according to https://libc.rip.
                - ``libc_base``: Base address of ``libc``.
        """
        assert state.leaks is not None

        URL = "https://libc.rip/api/find"
        LIBC_FILE = ".autorop.libc"
        formatted_leaks: Dict[str, str] = {}
        for symbol, address in state.leaks.items():
            formatted_leaks[symbol] = hex(address)

        log.info("Searching for libc based on leaks using libc.rip")
        r = requests.post(URL, json={"symbols": formatted_leaks})
        arutil.debug_requests(r)
        json = r.json()
        log.debug(repr(json))
        if len(json) == 0:
            log.error("could not find any matching libc!")
        if len(json) > 1:
            log.warning(f"{len(json)} matching libc's found, picking first one")

        log.info("Downloading libc")
        r = requests.get(json[0]["download_url"])
        arutil.debug_requests(r)
        with open(LIBC_FILE, "wb") as f:
            f.write(r.content)

        libc = ELF(LIBC_FILE)
        # pick first leak and use that to calculate base
        some_symbol, its_address = next(iter(state.leaks.items()))
        libc.address = its_address - libc.symbols[some_symbol]
        state.libc = LIBC_FILE
        state.libc_base = libc.address

        # sanity check
        for symbol, address in state.leaks.items():
            assert state.libc is not None
            diff = address - libc.symbols[symbol]
            if diff != 0:
                log.warning(
                    f"symbol {symbol} has delta with actual libc of {hex(diff)}"
                )

        return state
