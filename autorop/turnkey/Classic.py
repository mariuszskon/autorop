from autorop import PwnState, Pipe, Pipeline, arutil, bof, leak, libc, call


class Classic(Pipeline):
    def __init__(
        self,
        find: Pipe = bof.Corefile(),
        leak: Pipe = leak.Puts(),
        lookup: Pipe = libc.Auto(),
        shell: Pipe = call.SystemBinSh(),
    ):
        """Perform a "classic" attack against a binary.

        Launch a find-leak-lookup-shell attack against a binary.
        I made up this term.
        But it is a common pattern in CTFs.

        - Find: Find the vulnerability (e.g. how far we need to write to overwrite
          return address due to a buffer overflow).
        - Leak: Find out important stuff about our context (e.g. addresses of
          symbols in libc, PIE offset, etc.).
        - Lookup: Get data from elsewhere (e.g. download appropriate libc version).
        - Shell: Spawn a shell (e.g. via ret2libc, or via syscall).

        The default parameters perform a ret2libc attack on a non-PIE/non-ASLR target
        (at most one of these is fine, but not both), leaking with ``puts``.
        You can set ``state._elf.address`` yourself and it might work for PIE and ASLR.
        We use find the libc automatically (likely using libc.rip), and then spawn a shell on the target.

        Arguments:
            find: "Finder" of vulnerability. :mod:`autorop.bof` may be of interest.
            leak: "Leaker". :mod:`autorop.leak` may be of interest.
            lookup: "Lookup-er" of info. :mod:`autorop.libc` may be of interest.
            shell: Spawner of shell. :mod:`autorop.call` may be of interest.

        Returns:
            Function which takes a ``PwnState``, and returns the new ``PwnState``.
        """

        super().__init__(find, arutil.OpenTarget(), leak, lookup, shell)
