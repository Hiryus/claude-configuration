import re


def is_flag(text:str|None) -> bool:
    """
    A flag-shaped word, as opposed to a value that merely starts with a dash: the negative numbers
    some commands take are ordinary values (`--memory-swap -1`, `--oom-score-adj -500`).
    """
    return bool(text) and bool(re.match(r"^-\D", text or ""))
