from src.rules.rule import Rule
from clang.cindex import CursorKind

class UnusedVarRule(Rule):

    def check(self, cfg) -> list[dict]:
        declared_vars = {}  # name -> node
        used_vars = set()

        for block in cfg.reachable_blocks():
            for stmt in block.stmts:
                self._get_var_decls(stmt, declared_vars)
                self._get_var_uses(stmt, used_vars)

        issues = []
        for name, node in declared_vars.items():
            if name not in used_vars:
                loc = node.location
                issues.append({
                    "file": loc.file.name if loc.file else "<unknown>",
                    "line": loc.line,
                    "column": loc.column,
                    "severity": "WARNING",
                    "message": f"Variable '{name}' is declared but never used",
                })
        return issues

    def _get_var_decls(self, node, decls):
        if node.kind == CursorKind.VAR_DECL:
            decls[node.spelling] = node
            return
        for child in node.get_children():
            self._get_var_decls(child, decls)
    
    def _get_var_uses(self, node, used_vars):
        if node.kind == CursorKind.DECL_REF_EXPR:
            used_vars.add(node.spelling)
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2 and self._is_plain_assignment(node, children):
                used_vars.update(self._get_var_uses(children[1], used_vars))
                return used_vars
        for child in node.get_children():
            used_vars.update(self._get_var_uses(child, used_vars))
        return used_vars

    def _is_plain_assignment(self, node, children):
        """Return True if this BINARY_OPERATOR is a plain '=' assignment."""
        lhs_end = children[0].extent.end.offset
        rhs_start = children[1].extent.start.offset
        for tok in node.get_tokens():
            tok_start = tok.extent.start.offset
            if lhs_end <= tok_start < rhs_start and tok.spelling == "=":
                return True
        return False
