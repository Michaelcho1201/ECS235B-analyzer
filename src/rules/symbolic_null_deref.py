from src.rules.rule import SymbolicRule


class SymbolicNullDerefRule(SymbolicRule):
    CWE = "CWE-476"
    CVSS_RANGE = "5.0-8.9"
    RECOMMENDATION = (
        "Check that the pointer is not null before dereferencing it. "
        "Return an error, throw an exception, or use a safe fallback when the pointer is null."
    )

    def check_symbolic(self, cfg, symbolic_result) -> list[dict]:
        issues = []

        for block in cfg.reachable_blocks():
            path_conditions = symbolic_result.conditions_for_block(block.id)

            for stmt in block.stmts:
                self._check_stmt(stmt, path_conditions, issues)

        return issues

    def _check_stmt(self, node, path_conditions, issues):
        tokens = [t.spelling for t in node.get_tokens()]

        for i, tok in enumerate(tokens):
            if tok == "*" and i + 1 < len(tokens):
                ptr_name = tokens[i + 1]

                if self._known_null(ptr_name, path_conditions):
                    loc = node.location

                    issues.append({
                        "file": loc.file.name if loc.file else "<unknown>",
                        "line": loc.line,
                        "column": loc.column,
                        "severity": "ERROR",
                        "message": (
                            f"Possible null pointer dereference: pointer '{ptr_name}' "
                             f"is dereferenced on a path where it may be null"
                        ),
                        "cwe": self.CWE,
                        "cvss_range": self.CVSS_RANGE,
                        "recommendation": self.RECOMMENDATION,
                    })

            if i + 1 < len(tokens) and tokens[i + 1] == "->":
                ptr_name = tok

                if self._known_null(ptr_name, path_conditions):
                    loc = node.location

                    issues.append({
                        "file": loc.file.name if loc.file else "<unknown>",
                        "line": loc.line,
                        "column": loc.column,
                        "severity": "ERROR",
                        "message": (
                            f"Possible null pointer dereference: pointer '{ptr_name}' "
                            f"is used with '->' on a path where it may be null"
                        ),
                        "cwe": self.CWE,
                        "cvss_range": self.CVSS_RANGE,
                        "recommendation": self.RECOMMENDATION,
                    })

        for child in node.get_children():
            self._check_stmt(child, path_conditions, issues)

    def _known_null(self, var_name, path_conditions):
        null_values = ["nullptr", "NULL", "0"]

        for conditions in path_conditions:
            for cond in conditions:
                compact = cond.replace(" ", "")

                for null_value in null_values:
                    if compact == f"{var_name}=={null_value}":
                        return True

                    if compact == f"{null_value}=={var_name}":
                        return True

        return False