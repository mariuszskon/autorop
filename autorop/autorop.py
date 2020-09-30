#!/usr/bin/env python3
# autorop - automated solver of classic CTF pwn challenges, with flexibility in mind

from . import PwnState, turnkey
from pwn import sys, process, connect  # mypy needs this separately :/

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # exploit local binary
        binary = sys.argv[1]
        state = PwnState(binary, process(binary))
    elif len(sys.argv) == 4:
        # exploit remote
        binary, host, ip = sys.argv[1:]
        state = PwnState(binary, connect(host, int(ip)))
    else:
        print("Usage: autorop BINARY [HOST IP]")
        exit()

    result = turnkey.classic(state)
    result.target.interactive()
