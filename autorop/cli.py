# autorop - automated solver of classic CTF pwn challenges, with flexibility in mind

from autorop import PwnState, turnkey
from pwn import sys, process, connect  # mypy needs this separately :/


def main() -> None:
    if len(sys.argv) == 2:
        # exploit local binary
        binary = sys.argv[1]
        state = PwnState(binary, lambda: process(binary))
    elif len(sys.argv) == 4:
        # exploit remote
        binary, host, ip = sys.argv[1:]
        state = PwnState(binary, lambda: connect(host, int(ip)))
    else:
        print("Usage: autorop BINARY [HOST PORT]")
        exit()

    result = turnkey.Classic()(state)
    assert result.target is not None
    result.target.interactive()
