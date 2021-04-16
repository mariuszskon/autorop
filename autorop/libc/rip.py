from autorop import PwnState, arutil
from pwn import log, ELF
import requests
from typing import Dict


def rip(state: PwnState) -> PwnState:
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
    #log.info("search libc:" + repr(json))
    download_id=0
    if len(json) == 0:
        log.error("could not find any matching libc!")
    if len(json) > 1:
        log.warning(f"{len(json)} matching libc's found, picking by hand")
        for x in range(len(json)):
                print("%2d: %s" % (x, json[x]["id"]))
        while True:
            download_id = input("You can choose it by hand\nOr type 'exit' to quit:")
            print(download_id)
            if download_id.replace("\r").replace("\n") == "exit" or download_id.replace("\r").replace("\n")  == "quit":
                sys.exit(0)
                break
            try:
                download_id = int(download_id)
                break
            except:
                continue

    json_d=json[download_id]
    log.info("Downloading libc")
    r = requests.get(json_d["download_url"])
    arutil.debug_requests(r)
    print(state.libc_database_path + "/" +  json_d['id'] + ".so",)
    with open(state.libc_database_path  + "/" + json_d['id'] + ".so", "wb") as f:
        f.write(r.content)
    print(state.libc_database_path  + "/" + json_d['id'] + ".so download complete")
    print("Downloading symbols")
    r = requests.get(json_d["symbols_url"])
    with open(state.libc_database_path  + "/" + json_d['id'] + ".symbols", "wb") as f:
        f.write(r.content)
    with open(state.libc_database_path  + "/" + json_d['id'] + ".info", "wb") as f:
        f.write(bytes(json_d['id'], encoding = "utf8"))
    with open(state.libc_database_path  + "/" + json_d['id'] + ".url", "wb") as f:
        f.write(bytes(json_d["download_url"], encoding = "utf8"))
    print(json_d['id'] + ".symbols download complete")
    LIBC_FILE = str(str(state.libc_database_path)  + "//" + str(json_d['id'])+ ".so") 

    print("LIBC_FILE：" + str(LIBC_FILE))

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
            log.warning(f"symbol {symbol} has delta with actual libc of {hex(diff)}")

    return state
