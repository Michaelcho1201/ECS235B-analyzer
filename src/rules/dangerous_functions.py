from clang.cindex import CursorKind
from src.rules.rule import Rule

DANGEROUS = {"gets", "scanf", "strcpy", "strcat", "sprintf"}


class DangerousFunctionRule(Rule):
    """Flag calls to unsafe C functions on reachable execution paths."""

    def check(self, cfg) -> list[dict]:
        issues = []
        for block in cfg.reachable_blocks():
            for stmt in block.stmts:
                self._walk(stmt, issues)
        return issues

    def _walk(self, node, issues):
        if node.kind == CursorKind.CALL_EXPR and node.spelling in DANGEROUS:
            loc = node.location
            issues.append({
                "file": loc.file.name if loc.file else "<unknown>",
                "line": loc.line,
                "column": loc.column,
                "severity": "WARNING",
                "message": f"Unsafe function '{node.spelling}()' — use a safer alternative",
            })
        for child in node.get_children():
            self._walk(child, issues)
