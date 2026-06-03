from clang.cindex import CursorKind, TokenKind
from src.rules.rule import SymbolicRule


class SymbolicDivZeroRule(SymbolicRule):
    CWE = "CWE-369"
    CVSS_RANGE = "5.0-7.5"
    RECOMMENDATION = (
        "Validate that the divisor is nonzero before performing division, "
        "and handle zero input with an error path or safe default value."
    )

    def check_symbolic(self, cfg, symbolic_result) -> list[dict]:
        issues = []

        for block in cfg.reachable_blocks():
            path_conditions = symbolic_result.conditions_for_block(block.id)

            for stmt in block.stmts:
                self._walk(stmt, path_conditions, issues)

        return issues

    def _walk(self, node, path_conditions, issues):
        tokens = [t.spelling for t in node.get_tokens()]

        for i, tok in enumerate(tokens):
            if tok == "/" and i + 1 < len(tokens):
                divisor = tokens[i + 1]

                if self._known_zero(divisor, path_conditions):
                    loc = node.location

                    issues.append({
                        "file": loc.file.name if loc.file else "<unknown>",
                        "line": loc.line,
                        "column": loc.column,
                        "severity": "ERROR",
                        "message": (
                            f"Possible division by zero: expression divides by '{divisor}' "
                            f"on a path where '{divisor}' may be 0"
                        ),
                        "cwe": self.CWE,
                        "cvss_range": self.CVSS_RANGE,
                        "recommendation": self.RECOMMENDATION,
                    })

        for child in node.get_children():
            self._walk(child, path_conditions, issues)

    def _known_zero(self, var_name, path_conditions):
        for conditions in path_conditions:
            for cond in conditions:
                compact = cond.replace(" ", "")

                if compact == f"{var_name}==0":
                    return True

                if compact == f"0=={var_name}":
                    return True

        return False