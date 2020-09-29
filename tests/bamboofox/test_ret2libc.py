from .. import *


@flaky(max_runs=3)
def test_ret2libc_local(exploit_local):
    state = turnkey.classic(exploit_local("./tests/bamboofox/ret2libc"))
    have_shell(state.target)
