from pwn import log
import requests


def debug_requests(r: requests.Response) -> None:
    """Print debugging information on a HTTP response made with ``requests``.

    Arguments:
        r: The response whose contents are to be logged.
    """
    log.debug(repr(r.request.headers))
    log.debug(repr(r.request.body))
    log.debug(repr(r.headers))
    # log.debug(repr(r.content))  # often too big
