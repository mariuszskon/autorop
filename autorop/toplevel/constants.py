from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from autorop import PwnState

#: pwntools ``tube.clean(CLEAN_TIME)``, for removing excess output
CLEAN_TIME = 0.5

#: Stack alignment, in bytes
#: Ubuntu et al. on x86_64 require it
#: (https://ropemporium.com/guide.html#Common%20pitfalls)
#: and some 32 bit binaries perform ``and esp, 0xfffffff0`` in ``main``
STACK_ALIGNMENT = 16
