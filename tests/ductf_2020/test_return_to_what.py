from .. import *


@flaky(max_runs=3)
def test_return_to_what(exploit_local):
    state = turnkey.classic(exploit_local("./tests/ductf_2020/return-to-what"))
    have_shell(state.target)
