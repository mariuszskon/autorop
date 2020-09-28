from pwn import log
import requests


def debug_requests(r: requests.Response) -> None:
    """Print debugging information on a HTTP response."""
    log.debug(r.request.headers)
    log.debug(r.request.body)
    log.debug(r.headers)
    # log.debug(r.content)  # often too big
