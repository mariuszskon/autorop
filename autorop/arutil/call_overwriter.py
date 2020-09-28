from autorop import PwnState


def call_overwriter(state: PwnState, data: bytes) -> None:
    """Call `state.overwriter`, logging as necessary."""
    assert state.overwriter is not None  # make mypy happy
    state.overwriter(state.target, data)
