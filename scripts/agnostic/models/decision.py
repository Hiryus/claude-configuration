from dataclasses import dataclass
from enum import Enum


class Verdict(Enum):
    """
    What to do about one command. ALLOW < ASK < DENY in severity.
    """
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"

@dataclass(frozen=True)
class Decision:
    """
    The verdict for one command, and the reason behind it.
    """
    verdict:Verdict
    reason:str

    @staticmethod
    def allow(reason:str) -> "Decision":
        return Decision(Verdict.ALLOW, reason)

    @staticmethod
    def ask(reason:str) -> "Decision":
        return Decision(Verdict.ASK, reason)

    @staticmethod
    def deny(reason:str) -> "Decision":
        return Decision(Verdict.DENY, reason)
