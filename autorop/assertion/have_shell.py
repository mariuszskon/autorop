from autorop import constants
from pwn import tube, log


def have_shell(tube: tube) -> bool:
    """Check if the given tube is a shell, using a simple heuristic.

    Arguments:
        tube: The connection to check if we have a shell.

    Returns:
        ``True`` if the heuristic does think there is a shell, ``False`` otherwise.
    """
    tube.clean(constants.CLEAN_TIME)  # clean excess output
    tube.sendline("echo $0")
    line: bytes = tube.readline()
    rest = tube.clean(constants.CLEAN_TIME)
    log.debug(f"Shell response line: {line!r}")
    log.debug(f"Rest: {rest!r}")

    return line == b"/bin/sh\n"
