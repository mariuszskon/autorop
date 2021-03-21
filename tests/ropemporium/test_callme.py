from .. import *

CWD = "./tests/ropemporium/"
BIN32 = "./callme32"
BIN64 = "./callme"


def overwriter(t, data):
    t.sendline(data)
    t.readuntil(b"Thank you!\n")


def test_callme32_local(exploit):
    with cwd(CWD):
        state = exploit(BIN32, process(BIN32))
        state.overwriter = overwriter
        state = turnkey.classic()(state)
        assert have_shell(state.target)


def test_callme_local(exploit):
    with cwd(CWD):
        state = exploit(BIN64, process(BIN64))
        state.overwriter = overwriter
        state = turnkey.classic()(state)
        assert have_shell(state.target)
