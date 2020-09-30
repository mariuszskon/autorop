#!/usr/bin/env python3
# autorop - automated solver of classic CTF pwn challenges, with flexibility in mind

from . import *

if __name__ == "__main__":
    if len(sys.argv) == 2:
        # exploit local binary
        binary = sys.argv[1]
        result = turnkey.classic(PwnState(binary, process(binary)))
        result.target.interactive()
    elif len(sys.argv) == 4:
        # exploit remote
        binary, host, ip = sys.argv[1:]
        result = turnkey.classic(PwnState(binary, remote(host, int(ip))))
        result.target.interactive()
    else:
        print("Usage: autorop BINARY [HOST IP]")
        exit()
