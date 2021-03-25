from .. import *

BIN = "./tests/ductf_2020/return-to-what"


def test_return_to_what(exploit):
    state = exploit(BIN, lambda: process(BIN))
    state = turnkey.classic()(state)
    assert have_shell(state.target)
