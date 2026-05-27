import csv
from collections import defaultdict
from pathlib import Path

from clang.cindex import CursorKind

from src.rules.rule import Rule

# Functions whose return value is tainted (user-controlled data)
TAINT_CALL_SOURCES = {
    "getenv", "secure_getenv",
    "getopt", "getopt_long",
    "getchar", "fgetc", "getc",
    "accept",
    "popen",
    "gethostname", "uname", "readlink", "getcwd",
}

# Functions that write tainted data INTO a buffer argument.
# Value = index of the buffer argument that becomes tainted.
TAINT_ARG_SOURCES = {
    "gets":      0,
    "fgets":     0,
    "getline":   0,
    "getdelim":  0,
    "fread":     0,
    "read":      1,
    "recv":      1,
    "recvfrom":  1,
    "recvmsg":   1,
    "msgrcv":    1,
    "mq_receive": 0,
    "scanf":    -1,
    "fscanf":   -1,
    "sscanf":   -1,
}

# Global variables that are always tainted
TAINT_GLOBALS = {
    "argv",     
    "optarg",   
    "environ",
}

# Functions that sanitize their input, removing taint
SANITIZERS = {
    "strncpy", "snprintf", "vsnprintf",
    "sanitize_input", "validate_input", "escape_string",
    "mysql_real_escape_string",
    "htmlspecialchars", "htmlentities",
}


class TaintedDataRule(Rule):
    def __init__(self, csv_path="src/rules/dangerous_functionsfinal_database.csv"):
        self.sinks = self._load_sinks(csv_path)

    def _load_sinks(self, csv_path):
        sinks = {}
        path = Path(csv_path)
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) >= 6:
                    sinks[row[0]] = {
                        "cwe": row[1],
                        "severity": row[2],
                        "cvss": row[3],
                        "message": row[4],
                        "recommendation": row[5],
                    }
        return sinks

    def check(self, cfg) -> list[dict]:
        tainted = defaultdict()
        issues = []

        for block in cfg.reachable_blocks():
            for stmt in block.stmts:
                if stmt.kind == CursorKind.VAR_DECL:
                    self._process_var_decl(stmt, tainted)

                # Clang wraps VAR_DECL in DECL_STMT in the CFG
                elif stmt.kind == CursorKind.DECL_STMT:
                    for child in stmt.get_children():
                        if child.kind == CursorKind.VAR_DECL:
                            self._process_var_decl(child, tainted)

                elif stmt.kind == CursorKind.BINARY_OPERATOR:
                    self._process_assignment(stmt, tainted)

                elif stmt.kind == CursorKind.CALL_EXPR:
                    self._process_call_expr(stmt, tainted, issues)

        return issues


    def _process_var_decl(self, stmt, tainted):
        """Handle: int x = <expr>  or  char *s = <expr>"""
        children = list(stmt.get_children())

        if any(self._is_sanitizer_call(c) for c in children):
            tainted.pop(stmt.spelling, None)
            return

        if any(self._subtree_is_tainted(c, tainted) for c in children):
            tainted[stmt.spelling] = stmt

    def _process_assignment(self, stmt, tainted):
        """Handle: x = <expr>  (assignment to existing variable)"""
        children = list(stmt.get_children())
        if len(children) < 2:
            return
        lhs, rhs = children[0], children[1]
        if lhs.kind != CursorKind.DECL_REF_EXPR:
            return

        if self._is_sanitizer_call(rhs):
            tainted.pop(lhs.spelling, None)
        elif self._subtree_is_tainted(rhs, tainted):
            tainted[lhs.spelling] = lhs

    def _process_call_expr(self, stmt, tainted, issues):
        """Handle standalone call statements: sanitize, propagate taint, or detect sinks."""
        name = stmt.spelling
        call_args = list(stmt.get_children())[1:]

        if name in SANITIZERS:
            for arg in call_args:
                if arg.kind == CursorKind.DECL_REF_EXPR:
                    tainted.pop(arg.spelling, None)
            return

        if name in self.sinks:
            for arg in call_args:
                tainted_ref = self._find_tainted_ref(arg, tainted)
                if tainted_ref:
                    issues.append(self._make_sink_issue(stmt, tainted_ref, self.sinks[name]))
                    break

        if name in TAINT_ARG_SOURCES:
            buf_idx = TAINT_ARG_SOURCES[name]
            if buf_idx == -1:
                for arg in call_args[1:]:
                    var = self._unwrap_ref(arg)
                    if var:
                        tainted[var] = arg
            elif buf_idx < len(call_args):
                var = self._unwrap_ref(call_args[buf_idx])
                if var:
                    tainted[var] = call_args[buf_idx]

    def _unwrap_ref(self, node):
        """Return the variable name if node is (or wraps) a DECL_REF_EXPR."""
        if node.kind == CursorKind.DECL_REF_EXPR:
            return node.spelling
        for child in node.get_children():
            result = self._unwrap_ref(child)
            if result:
                return result
        return None

    def _find_tainted_ref(self, node, tainted):
        """Return the first tainted DECL_REF_EXPR node in this subtree."""
        if node.kind == CursorKind.DECL_REF_EXPR and self._is_tainted(node, tainted):
            return node
        for child in node.get_children():
            result = self._find_tainted_ref(child, tainted)
            if result:
                return result
        return None

    def _subtree_is_tainted(self, node, tainted):
        """Return True if this AST subtree contains any taint source."""
        if self._node_is_taint_source(node, tainted):
            return True
        return any(self._subtree_is_tainted(c, tainted) for c in node.get_children())

    def _node_is_taint_source(self, node, tainted):
        if node.kind == CursorKind.DECL_REF_EXPR and node.spelling in TAINT_GLOBALS:
            return True

        if node.kind == CursorKind.CALL_EXPR and node.spelling in TAINT_CALL_SOURCES:
            return True

        if node.kind == CursorKind.DECL_REF_EXPR and node.spelling in tainted:
            return True

        return False

    def _is_sanitizer_call(self, node):
        return node.kind == CursorKind.CALL_EXPR and node.spelling in SANITIZERS

    def _is_tainted(self, node, tainted):
        return node.spelling in tainted or node.spelling in TAINT_GLOBALS

    def _make_sink_issue(self, call_node, tainted_ref, sink_info):
        loc = call_node.location
        return {
            "file": loc.file.name if loc.file else "<unknown>",
            "line": loc.line,
            "column": loc.column,
            "severity": sink_info["severity"],
            "message": (
                f"Tainted variable '{tainted_ref.spelling}' passed to "
                f"dangerous function '{call_node.spelling}()'. {sink_info['message']}"
            ),
            "cwe": sink_info["cwe"],
            "cvss_range": sink_info["cvss"],
            "recommendation": sink_info["recommendation"],
        }
