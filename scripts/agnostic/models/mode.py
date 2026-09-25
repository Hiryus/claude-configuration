from enum import Enum


class Mode(Enum):
    """
    How much autonomy the call runs with.
    """
    MANUAL = "manual"  # the user validates most calls
    EDIT = "edit"      # most edits are pre-approved
    AUTO = "auto"      # the agent runs unattended

    @staticmethod
    def of(name: str|None) -> "Mode":
        """
        The mode of that name.
        Anything else (nothing recorded yet, a typo, a name from another version) is MANUAL.
        """
        wanted = (name or "").strip().lower()
        return next((mode for mode in Mode if mode.value == wanted), Mode.MANUAL)
