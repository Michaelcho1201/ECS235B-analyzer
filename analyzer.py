import sys
import clang.cindex as clang
from clang.cindex import CursorKind

from src.parser.parser import CFGBuilder
from src.rules.dangerous_functions import DangerousFunctionRule
from src.rules.uninitialized_var import UninitializedVarRule
from src.rules.unused_var import UnusedVarRule
from src.rules.tainted_data import TaintedDataRule

SEVERITY_LABELS = {
    0: "NOTE",
    1: "WARNING",
    2: "ERROR",
    3: "FATAL",
}

RULES = [
    DangerousFunctionRule("src/rules/dangerous_functionsfinal_database.csv"),
    UninitializedVarRule(),
    UnusedVarRule(),
    # TaintedDataRule(),
]


class Analyzer:
    def __init__(self):
        self.index = clang.Index.create()
        self.issues = []

    def analyze(self, file_path):
        tu = self.index.parse(file_path, args=["-std=c++23"])
        self._collect_diagnostics(tu)
        builder = CFGBuilder()
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                cfg = builder.build(cursor)
                for rule in RULES:
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
