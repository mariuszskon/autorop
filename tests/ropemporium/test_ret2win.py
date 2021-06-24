from .. import *

BIN32 = "./tests/ropemporium/ret2win32"
BIN64 = "./tests/ropemporium/ret2win"


def test_ret2win32_local(exploit):
    state = exploit(BIN32, lambda: process(BIN32))
    state = Pipeline(bof.corefile, arutil.open_target, call.custom("ret2win"))(state)
    assert b"Well done! Here's your flag:" in state.target.clean(constants.CLEAN_TIME)


def test_ret2win_local(exploit):
    state = exploit(BIN64, lambda: process(BIN64))
    # align not strictly needed but inreases test line coverage ;)
    state = Pipeline(
        bof.corefile, arutil.open_target, call.custom("ret2win", align=True)
    )(state)
    assert b"Well done! Here's your flag:" in state.target.clean(constants.CLEAN_TIME)
