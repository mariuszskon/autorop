from autorop import *
import pytest
from flaky import flaky


@flaky(max_runs=3)
@pytest.mark.parametrize(
    "local_get_shell", ["./tests/ductf_2020/return-to-what"], indirect=True
)
def test_return_to_what(local_get_shell):
    turnkey.classic(local_get_shell)
