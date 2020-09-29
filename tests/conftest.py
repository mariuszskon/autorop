# common functions/fixtures which can be reused throughout tests
from autorop import *
import pytest


@pytest.fixture
def exploit_local():
    """Fixture for running a binary locally."""
    # somewhat hacky code to allow us to easily pass a parameter
    wrapper = []

    def inner(binary):
        wrapper.append(PwnState(binary, process(binary)))
        return wrapper[0]

    yield inner
    wrapper[0].target.close()


def have_shell(tube):
    """Cheks if the given tube is a shell, using a simple heuristic."""
    tube.clean(1)  # clean excess output
    tube.sendline("echo $0")
    assert tube.readline() == b"/bin/sh\n"
