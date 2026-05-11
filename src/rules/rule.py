from abc import ABC, abstractmethod
from src.parser.parser import CFG


class Rule(ABC):
    @abstractmethod
    def check(self, cfg: CFG) -> list[dict]:
        """Run the rule against a function's CFG and return a list of issues."""
        ...
