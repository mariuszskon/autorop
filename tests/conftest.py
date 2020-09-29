# pytest fixtures and utilities to make tests beautiful
from autorop import *
import pytest


def have_shell(tube):
    """Check if the given `tube` gives us a shell, using a simple heuristic."""
    tube.clean(1)  # remove any stray output
    tube.sendline("echo $0")  # get argv[0] (name of this process)
    assert tube.readline() == b"/bin/sh\n"


# https://stackoverflow.com/questions/18011902/pass-a-parameter-to-a-fixture-function
@pytest.fixture
def local_get_shell(request):
    """Produce a `PwnState` targeting a local process, checking if we get a shell."""
    s = PwnState(request.param, process(request.param))
    yield s
    have_shell(s.target)
