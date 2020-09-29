from .. import *

BIN = "./tests/ductf_2020/return-to-what"


@flaky(max_runs=3)
def test_return_to_what(exploit):
    state = exploit(BIN, process(BIN))
    state = turnkey.classic(state)
    have_shell(state.target)
