from src.rules.rule import SymbolicRule


class SymbolicOutOfBoundsRule(SymbolicRule):
    CWE = "CWE-125"
    CVSS_RANGE = "6.0-9.8"
    RECOMMENDATION = (
        "Validate array indexes before use. "
        "Ensure the index is greater than or equal to 0 and strictly less than the array size."
    )

    def check_symbolic(self, cfg, symbolic_result) -> list[dict]:
        issues = []

        array_sizes = {}

        for block in cfg.reachable_blocks():
            for stmt in block.stmts:
                array_sizes.update(self._collect_local_arrays(stmt))

        for block in cfg.reachable_blocks():
            path_conditions = symbolic_result.conditions_for_block(block.id)

            for stmt in block.stmts:
                self._check_stmt(stmt, array_sizes, path_conditions, issues)

        return issues

    def _collect_local_arrays(self, node):
        tokens = [t.spelling for t in node.get_tokens()]
        arrays = {}

        for i in range(len(tokens) - 3):
            name = tokens[i + 1]

            if tokens[i + 2] == "[" and tokens[i + 3].isdigit():
                arrays[name] = int(tokens[i + 3])

        return arrays

    def _check_stmt(self, node, array_sizes, path_conditions, issues):
        tokens = [t.spelling for t in node.get_tokens()]

        for i in range(len(tokens) - 3):
            array_name = tokens[i]

            if tokens[i + 1] == "[":
                index_name = tokens[i + 2]

                if array_name in array_sizes:
                    size = array_sizes[array_name]

                    if self._known_out_of_bounds(index_name, size, path_conditions):
                        loc = node.location

                        issues.append({
                            "file": loc.file.name if loc.file else "<unknown>",
                            "line": loc.line,
                            "column": loc.column,
                            "severity": "ERROR",
                            "message": (
                                f"Possible out-of-bounds array access: array '{array_name}' "
                                f"has size {size}, but index '{index_name}' may be outside "
                                f"the valid range on this path"
                            ),
                            "cwe": self.CWE,
                            "cvss_range": self.CVSS_RANGE,
                            "recommendation": self.RECOMMENDATION,
                        })

        for child in node.get_children():
            self._check_stmt(child, array_sizes, path_conditions, issues)

    def _known_out_of_bounds(self, index_name, size, path_conditions):
        for conditions in path_conditions:
            for cond in conditions:
                compact = cond.replace(" ", "")

                if compact == f"{index_name}>={size}":
                    return True

                if compact == f"{index_name}>{size - 1}":
                    return True

                if compact == f"{size}<={index_name}":
                    return True

                if compact == f"{size - 1}<{index_name}":
                    return True

                if compact == f"{index_name}<0":
                    return True

                if compact == f"0>{index_name}":
                    return True

        return False