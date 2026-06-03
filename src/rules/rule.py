from abc import ABC, abstractmethod
from src.parser.parser import CFG


class Rule(ABC):
    @abstractmethod
    def check(self, cfg: CFG) -> list[dict]:
        """Run the rule against a function's CFG and return a list of issues."""
        ...
class SymbolicRule(ABC):
    requires_symbolic = True

    @abstractmethod
    def check_symbolic(self, cfg: CFG, symbolic_result) -> list[dict]:
        """Run the rule using symbolic execution results."""
        ...
