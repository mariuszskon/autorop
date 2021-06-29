from typing import Iterable, Any


def pretty_function(name: str, args: Iterable[Any]) -> str:
    """Produce a pretty textual description of a function call.

    Produce a string describing a function call. This is of the form:
    name(args[0], args[1], ...)

    Arguments:
        name: Name of function.
        args: The arguments passed to said function.

    Returns:
        Textual description of function call to the function name
        with the provided arguments.
    """
    pretty_args = ", ".join(repr(x) for x in args)
    return f"{name}({pretty_args})"
