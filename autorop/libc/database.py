from autorop import PwnState
from pwn import log, ELF, re, subprocess
from typing import List
from dataclasses import replace

LIBC_NAME_REGEX = re.compile(r"^.* \((.*)\)$")


def database(state: PwnState) -> PwnState:
    """Acquire libc version using local installation of `libc-database <https://github.com/niklasb/libc-database>`_

    We can programmatically find libc based on function address leaks
    (two or more preferred). This function sets ``state.libc``, including setting
    ``state.libc.address`` for ready-to-use address calculation.

    Arguments:
        state: The current ``PwnState`` with the following set

            - ``leaks``: Leaked symbols of libc.
            - ``libc_database_path``: Path to libc-database installation.

    Returns:
        New ``PwnState``, with the following updated

            - ``libc``: Path to ``target``'s libc.
            - ``libc_base``: Base address of ``libc``.
    """
    assert state.leaks is not None
    assert state.libc_database_path is not None

    flattened_args: List[str] = []
    for symbol, address in state.leaks.items():
        flattened_args.append(symbol)
        flattened_args.append(hex(address))

    log.info("Searching for libc based on leaks")
    command = [state.libc_database_path + "/find"] + flattened_args
    results = (
        subprocess.run(command, check=True, stdout=subprocess.PIPE)
        .stdout.decode("utf-8")
        .splitlines()
    )
    log.debug(repr(results))
    if len(results) == 0:
        log.error("could not find any matching libc!")
    if len(results) > 1:
        log.warning(f"{len(results)} matching libc's found, picking first one")

    # parse the output
    libc_name = LIBC_NAME_REGEX.fullmatch(results[0]).group(1)
    path_to_libc = f"{state.libc_database_path}/db/{libc_name}.so"

    libc = ELF(path_to_libc)
    # pick first leak and use that to calculate base
    some_symbol, its_address = next(iter(state.leaks.items()))
    libc.address = its_address - libc.symbols[some_symbol]
    state = replace(state, libc=path_to_libc, libc_base=libc.address)

    # sanity check
    for symbol, address in state.leaks.items():
        assert state.libc is not None
        diff = address - libc.symbols[symbol]
        if diff != 0:
            log.warning(f"symbol {symbol} has delta with actual libc of {hex(diff)}")

    return state
