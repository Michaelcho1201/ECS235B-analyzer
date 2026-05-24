import csv
from pathlib import Path
from clang.cindex import CursorKind
from src.rules.rule import Rule


class DangerousFunctionRule(Rule):
    """Flag calls to unsafe C/C++ functions using the CSV database."""

    def __init__(self, csv_path="src/rules/dangerous_functionsfinal_database.csv"):
        self.entries = self._load_csv_entries(csv_path)

    def _load_csv_entries(self, csv_path):
        entries = {}

        csv_path = Path(csv_path)

        with csv_path.open("r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader, None)

            for row in reader:
                if len(row) >= 6:
                    function_name = row[0]
                    entries[function_name] = {
                        "cwe": row[1],
                        "severity": row[2],
                        "cvss": row[3],
                        "message": row[4],
                        "recommendation": row[5],
                    }

        return entries

    def check(self, cfg) -> list[dict]:
        issues = []

        for block in cfg.reachable_blocks():
            for stmt in block.stmts:
                self._walk(stmt, issues)

        return issues

    def _walk(self, node, issues):
        if node.kind == CursorKind.CALL_EXPR:
            function_name = node.spelling
            entry = self.entries.get(function_name)

            if entry is not None:
                loc = node.location

                issues.append({
                    "file": loc.file.name if loc.file else "<unknown>",
                    "line": loc.line,
                    "column": loc.column,
                    "severity": entry["severity"],
                    "message": (
                        f"Unsafe function '{function_name}()' found. "
                        f"CWE: {entry['cwe']}. "
                        f"CVSS: {entry['cvss']}. "
                        f"{entry['message']} "
                        f"Recommendation: {entry['recommendation']}"
                    ),
                })

        for child in node.get_children():
            self._walk(child, issues)
