import sys
import clang.cindex as clang
from clang.cindex import CursorKind

from src.parser.parser import CFGBuilder
from src.rules.buffer_overflow import BufferOverflowRule
from src.rules.dangerous_functions import DangerousFunctionRule
from src.rules.function_summary import SummaryBuilder, SummaryDatabase
from src.rules.memory_leak import MemoryLeakRule, RESOURCE_REGISTRY, _ALLOC_FUNCS, _DEALLOC_FUNCS
from src.rules.uninitialized_var import UninitializedVarRule
from src.rules.unused_var import UnusedVarRule

SEVERITY_LABELS = {
    0: "IGNORED",
    1: "NOTE",
    2: "WARNING",
    3: "ERROR",
    4: "FATAL",
}


class Analyzer:
    def __init__(self):
        self.index = clang.Index.create()
        self.issues = []

    def analyze(self, file_path):
        self.issues = []
        tu = self.index.parse(file_path, args=["-std=c++23"])
        self._collect_diagnostics(tu)

        builder = CFGBuilder()
        summary_db = SummaryDatabase()
        dealloc_for: dict[str, str] = {k: v[0] for k, v in RESOURCE_REGISTRY.items()}

        summary_builder = SummaryBuilder(
            alloc_funcs=_ALLOC_FUNCS,
            dealloc_funcs=_DEALLOC_FUNCS,
            dealloc_for=dealloc_for,
        )

        func_cfgs: list[tuple] = []
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                cfg = builder.build(cursor)
                func_cfgs.append((cursor, cfg))
                summary = summary_builder.build(cursor, cfg)
                summary_db.add(cursor, summary)

        rules = [
            DangerousFunctionRule("src/rules/dangerous_functionsfinal_database.csv"),
            BufferOverflowRule(),
            MemoryLeakRule(summary_db=summary_db),
            UninitializedVarRule(),
            UnusedVarRule(),
        ]

        for _cursor, cfg in func_cfgs:
            for rule in rules:
                self.issues.extend(rule.check(cfg))

        return self.issues

    def _collect_diagnostics(self, tu):
        for diag in tu.diagnostics:
            f = diag.location.file
            self.issues.append({
                "file": f.name if f is not None else "<unknown>",
                "line": diag.location.line,
                "column": diag.location.column,
                "severity": SEVERITY_LABELS.get(diag.severity, "UNKNOWN"),
                "message": diag.spelling,
            })


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <file>")
        sys.exit(1)

    file_path = sys.argv[1]
    print(f"Analyzing: {file_path}")

    analyzer = Analyzer()
    issues = analyzer.analyze(file_path)

    if not issues:
        print("No issues found.")
    else:
        for issue in issues:
            sev = issue["severity"]
            col = issue.get("column", 0)
            print(f"[{sev}] {issue['file']}:{issue['line']}:{col} — {issue['message']}")

    print("Done")
