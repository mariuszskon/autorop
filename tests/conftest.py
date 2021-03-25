# common functions/fixtures which can be reused throughout tests
from autorop import *
import pytest
from contextlib import contextmanager


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
        if wrapper[0].target is not None:
            wrapper[0].target.close()
    except BrokenPipeError:
        pass

    # remove corefiles to prevent pwntools from getting lost later
    os.system("rm core.*")


def have_shell(tube):
    """Cheks if the given tube is a shell, using a simple heuristic."""
    tube.clean(1)  # clean excess output
    tube.sendline("echo $0")
    line = tube.readline()
    rest = tube.clean(1)
    log.debug(f"Shell response line: {line}")
    log.debug(f"Rest: {rest}")
    return line == b"/bin/sh\n"


# https://stackoverflow.com/a/37996581
@contextmanager
def cwd(path):
    oldpwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(oldpwd)
