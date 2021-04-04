from .. import *

CWD = "./tests/ropemporium/"
BIN32 = "./callme32"
BIN64 = "./callme"


def test_callme32_local(exploit):
    with cwd(CWD):
        state = exploit(BIN32, lambda: process(BIN32))
        state = turnkey.classic()(state)
        assert assertion.have_shell(state.target)


def test_callme_local(exploit):
    with cwd(CWD):
        state = exploit(BIN64, lambda: process(BIN64))
        state = turnkey.classic()(state)
        assert assertion.have_shell(state.target)
