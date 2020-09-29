from autorop import *
import pytest
from flaky import flaky


@flaky(max_runs=3)
@pytest.mark.parametrize(
    "local_get_shell", ["./tests/bamboofox/ret2libc"], indirect=True
)
def test_ret2libc_local(local_get_shell):
    turnkey.classic(local_get_shell)
