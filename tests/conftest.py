# common functions/fixtures which can be reused throughout tests
from autorop import *
import pytest


@pytest.fixture
def exploit():
    """Fixture for testing a local binary running through a `tube`."""
    # somewhat hacky code to allow us to easily pass a parameter
    wrapper = []

    def inner(binary, tube):
        wrapper.append(PwnState(binary, tube))
        return wrapper[0]

    yield inner
    try:
        wrapper[0].target.close()
    except BrokenPipeError:
        pass


def have_shell(tube):
    """Cheks if the given tube is a shell, using a simple heuristic."""
    tube.clean(1)  # clean excess output
    tube.sendline("echo $0")
    return tube.readline() == b"/bin/sh\n"
