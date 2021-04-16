from autorop import PwnState
from pwn import log, ELF, re, subprocess
from typing import List
import os,sys

LIBC_NAME_REGEX = re.compile(r"^.* \((.*)\)$")

def pmore(libc_database_path,result):
    result = result[:-8]  # .strip(".symbols")
    fd = open(libc_database_path  + "/db/"+ result + ".info")
    info = fd.read().strip()
    return("%s (id %s)" % (info, result))
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
        Mutated ``PwnState``, with the following updated

            - ``libc``: Path to ``target``'s libc.
            - ``libc_base``: Base address of ``libc``.
    """
    assert state.leaks is not None
    assert state.libc_database_path is not None
    condition = {}

    flattened_args: List[str] = []
    for symbol, address in state.leaks.items():
        condition[symbol] = address
        #flattened_args.append(symbol)
        #flattened_args.append(hex(address))
    res = []
    for name, address in condition.items():
        addr_last12 = address & 0xfff
        res.append(re.compile("^%s .*%x" % (name, addr_last12)))


    files = []
    # only read "*.symbols" file to find
    for _, _, f in os.walk(state.libc_database_path):
        for i in f:
            files += re.findall('^.*symbols$', i)


    find_libc = []
    for ff in files:
        print(ff)
        fd = open(state.libc_database_path + "/db/"+ ff, "rb")
        data = fd.read().decode(errors='ignore').split("\n")
        for x in res:
            if any(map(lambda line: x.match(line), data)):
                find_libc.append(ff)
        fd.close()

    libc_name=""
    if len(find_libc) == 0:
        print("No matched libc, please add more libc or try others")
        sys.exit(0)
    if len(find_libc) > 1:
        print("Multi Results:")
        for x in range(len(find_libc)):
            print("%2d: %s" % (x, pmore(state.libc_database_path , find_libc[x])))
        while True:
            in_id = input(
                "You can choose it by hand\nOr type 'exit' to quit:")
            if in_id == "exit" or in_id == "quit":
                sys.exit(0)
            try:
                in_id = int(in_id)
                libc_name = find_libc[in_id]
                break
            except:
                continue
    else:
        libc_name = find_libc[0]
    print("[+] %s be choosed." % pmore(state.libc_database_path ,libc_name))
    #print("libc_name:" + libc_name)
    libc_name=libc_name.replace(".symbols","")
    path_to_libc = f"{state.libc_database_path}/db/{libc_name}.so"
    #print("libc path:" + path_to_libc)

    libc = ELF(path_to_libc)
    # pick first leak and use that to calculate base
    some_symbol, its_address = next(iter(state.leaks.items()))
    libc.address = its_address - libc.symbols[some_symbol]
    state.libc = path_to_libc
    state.libc_base = libc.address

    # sanity check
    for symbol, address in state.leaks.items():
        assert state.libc is not None
        diff = address - libc.symbols[symbol]
        if diff != 0:
            log.warning(f"symbol {symbol} has delta with actual libc of {hex(diff)}")

    return state
