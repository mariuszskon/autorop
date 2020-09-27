from autorop import *


def test_return_to_what():
    BIN = "./tests/ductf_2020/return-to-what"
    s = PwnState(BIN, process(BIN))
    pipeline(s, bof_corefile)


if __name__ == "__main__":
    test_return_to_what()
