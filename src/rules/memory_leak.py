from __future__ import annotations

from collections import deque
from enum import Enum
from typing import TYPE_CHECKING

from clang.cindex import CursorKind

from src.rules.rule import Rule

if TYPE_CHECKING:
    from src.rules.function_summary import SummaryDatabase


class _RState(Enum):
    ALLOCATED = "ALLOCATED"
    FREED     = "FREED"
    ESCAPED   = "ESCAPED"


RESOURCE_REGISTRY: dict[str, tuple[str, str]] = {
    "malloc":   ("free",     "heap memory"),
    "calloc":   ("free",     "heap memory"),
    "realloc":  ("free",     "heap memory"),
    "strdup":   ("free",     "heap memory"),
    "strndup":  ("free",     "heap memory"),
    "fopen":    ("fclose",   "FILE handle"),
    "fdopen":   ("fclose",   "FILE handle"),
    "freopen":  ("fclose",   "FILE handle"),
    "popen":    ("pclose",   "pipe"),
    "open":     ("close",    "file descriptor"),
    "creat":    ("close",    "file descriptor"),
    "socket":   ("close",    "socket"),
    "accept":   ("close",    "socket"),
    "opendir":  ("closedir", "directory stream"),
}

_ALLOC_FUNCS:   frozenset[str] = frozenset(RESOURCE_REGISTRY)
_DEALLOC_FUNCS: frozenset[str] = frozenset(v[0] for v in RESOURCE_REGISTRY.values())

# CWE/CVSS metadata per issue type — stored as separate fields per Rita's feedback
_ISSUE_RESOURCE_LEAK = {
    "cwe": "CWE-401",
    "cvss_range": "5.5",
    "recommendation": "Ensure all allocated resources are freed before function exits on all paths.",
}
_ISSUE_DOUBLE_FREE = {
    "cwe": "CWE-415",
    "cvss_range": "7.5",
    "recommendation": "Ensure each resource is freed exactly once.",
}
_ISSUE_WRONG_DEALLOC = {
    "cwe": "CWE-762",
    "cvss_range": "6.5",
    "recommendation": "Use the matching deallocation function for each resource type.",
}


def _join(s1: _RState, s2: _RState) -> _RState:
    if s1 == s2:
        return s1
    if _RState.ALLOCATED in (s1, s2):
        return _RState.ALLOCATED
    return _RState.ESCAPED


class MemoryLeakRule(Rule):

    def __init__(self, summary_db: "SummaryDatabase | None" = None) -> None:
        self.summary_db = summary_db

    def check(self, cfg) -> list[dict]:
        self._issues: list[dict] = []
        self._reported: set[tuple] = set()
        self._alloc_info: dict[str, tuple[str, int, int, str]] = {}
        self._expected_dealloc: dict[str, str] = {}
        self._resource_label:   dict[str, str] = {}
        self._alias_of: dict[str, str] = {}

        block_edge_out: dict[tuple[int, int], dict[str, _RState]] = {}

        block_out: dict[int, dict[str, _RState] | None] = {
            b.id: None for b in cfg.blocks
        }

        worklist: deque = deque([cfg.entry])
        in_wl: set[int] = {cfg.entry.id}

        while worklist:
            block = worklist.popleft()
            in_wl.discard(block.id)

            merged: dict[str, _RState] = {}
            for pred in block.preds:
                edge_key = (pred.id, block.id)
                pred_out = block_edge_out.get(edge_key, block_out[pred.id])
                if pred_out is None:
                    continue
                for vk, st in pred_out.items():
                    merged[vk] = _join(merged[vk], st) if vk in merged else st

            cur: dict[str, _RState] = dict(merged)
            for stmt in block.stmts:
                self._transfer(stmt, cur)

            null_check = self._detect_null_check(block.stmts)
            if null_check and len(block.succs) == 2:
                null_var_key, null_on_true = null_check
                if null_var_key in cur and cur[null_var_key] == _RState.ALLOCATED:
                    cur_null = {k: v for k, v in cur.items() if k != null_var_key}
                    for i, succ in enumerate(block.succs):
                        on_true_branch = (i == 0)
                        edge_state = cur_null if (on_true_branch == null_on_true) else cur
                        block_edge_out[(block.id, succ.id)] = edge_state
                        if succ.id not in in_wl:
                            worklist.append(succ)
                            in_wl.add(succ.id)
                    block_out[block.id] = cur
                    continue

            if cur != block_out[block.id]:
                block_out[block.id] = cur
                for succ in block.succs:
                    if succ.id not in in_wl:
                        worklist.append(succ)
                        in_wl.add(succ.id)

        exit_in: dict[str, _RState] = {}
        for pred in cfg.exit_block.preds:
            edge_key = (pred.id, cfg.exit_block.id)
            pred_out = block_edge_out.get(edge_key, block_out[pred.id])
            if pred_out is None:
                continue
            for vk, st in pred_out.items():
                exit_in[vk] = _join(exit_in[vk], st) if vk in exit_in else st

        reported_sources: set[str] = set()
        for vk, st in exit_in.items():
            if st == _RState.ALLOCATED:
                src = self._get_source(vk)
                if src in reported_sources:
                    continue
                reported_sources.add(src)
                info = self._alloc_info.get(src) or self._alloc_info.get(vk)
                if info:
                    file_, line, col, name = info
                    label = self._resource_label.get(src) or self._resource_label.get(vk, "memory")
                    self._emit(
                        file_, line, col, "WARNING",
                        f"Resource leak: '{name}' ({label}) allocated here is never released on all paths",
                        _ISSUE_RESOURCE_LEAK,
                    )

        return self._issues

    def _detect_null_check(self, stmts: list) -> tuple[str, bool] | None:
        for stmt in reversed(stmts):
            result = self._parse_null_check(stmt)
            if result is not None:
                return result
        return None

    def _parse_null_check(self, node) -> tuple[str, bool] | None:
        k = node.kind

        if k == CursorKind.UNARY_OPERATOR:
            children = list(node.get_children())
            if children and self._is_logical_not(node, children):
                inner = children[0]
                vk = self._ref_key(inner)
                if vk is None and inner.kind in self._TRANSPARENT:
                    inner_ch = list(inner.get_children())
                    if inner_ch:
                        vk = self._ref_key(inner_ch[0])
                if vk is not None:
                    return (vk, True)

        if k == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                op = self._binop_token(node, children)
                if op in ("==", "!="):
                    lhs, rhs = children
                    lk = self._ref_key(lhs)
                    rk = self._ref_key(rhs)
                    if lk and self._is_null_literal(rhs):
                        return (lk, op == "==")
                    if rk and self._is_null_literal(lhs):
                        return (rk, op == "==")

        if k in (CursorKind.IF_STMT, *self._TRANSPARENT):
            for child in node.get_children():
                result = self._parse_null_check(child)
                if result is not None:
                    return result

        return None

    @staticmethod
    def _is_null_literal(node) -> bool:
        if node.kind == CursorKind.CXX_NULL_PTR_LITERAL_EXPR:
            return True
        if node.kind == CursorKind.GNU_NULL_EXPR:
            return True
        if node.kind == CursorKind.INTEGER_LITERAL:
            return [t.spelling for t in node.get_tokens()] == ["0"]
        if node.kind == CursorKind.UNEXPOSED_EXPR:
            for child in node.get_children():
                if MemoryLeakRule._is_null_literal(child):
                    return True
        return False

    @staticmethod
    def _is_logical_not(node, children) -> bool:
        if not children:
            return False
        child_start = children[0].extent.start.offset
        for tok in node.get_tokens():
            if tok.extent.start.offset < child_start and tok.spelling == "!":
                return True
        return False

    @staticmethod
    def _binop_token(node, children) -> str:
        lhs_end   = children[0].extent.end.offset
        rhs_start = children[1].extent.start.offset
        for tok in node.get_tokens():
            if lhs_end <= tok.extent.start.offset < rhs_start:
                return tok.spelling
        return ""

    def _get_source(self, vk: str) -> str:
        seen: set[str] = set()
        while vk in self._alias_of and vk not in seen:
            seen.add(vk)
            vk = self._alias_of[vk]
        return vk

    def _record_alias(self, new_vk: str, origin_vk: str) -> None:
        src = self._get_source(origin_vk)
        self._alias_of[new_vk] = src
        if src in self._expected_dealloc:
            self._expected_dealloc[new_vk] = self._expected_dealloc[src]
        if src in self._resource_label:
            self._resource_label[new_vk] = self._resource_label[src]

    def _free_allocation(self, vk: str, node, st: dict[str, _RState], arg_name: str, dealloc_fn: str = "free") -> None:
        src = self._get_source(vk)

        current_state = st.get(src) if src in st else st.get(vk)
        if current_state == _RState.FREED:
            self._report_double_free(node, arg_name)
            return

        expected = self._expected_dealloc.get(src) or self._expected_dealloc.get(vk)
        if expected and dealloc_fn != expected:
            label = self._resource_label.get(src) or self._resource_label.get(vk, "resource")
            loc = node.location
            self._emit(
                loc.file.name if loc.file else "<unknown>",
                loc.line, loc.column, "ERROR",
                f"Wrong dealloc: '{arg_name}' is a {label}; use '{expected}' not '{dealloc_fn}'",
                _ISSUE_WRONG_DEALLOC,
            )

        st[vk] = _RState.FREED
        if src in st:
            st[src] = _RState.FREED
        for alias_vk, alias_src in self._alias_of.items():
            if alias_src == src and alias_vk in st:
                st[alias_vk] = _RState.FREED

    def _transfer(self, node, st: dict[str, _RState]) -> None:
        k = node.kind

        if k == CursorKind.VAR_DECL:
            vk = self._var_key(node)
            children = list(node.get_children())
            if children:
                alloc_result = self._find_alloc_in(children)
                if alloc_result is not None:
                    alloc_node, dealloc_fn, label = alloc_result
                    st[vk] = _RState.ALLOCATED
                    loc = node.location
                    self._alloc_info[vk] = (
                        loc.file.name if loc.file else "<unknown>",
                        loc.line, loc.column, node.spelling,
                    )
                    self._expected_dealloc[vk] = dealloc_fn
                    self._resource_label[vk]   = label
                else:
                    rk = self._first_ref_key(children)
                    if rk is not None and rk in st:
                        st[vk] = st[rk]
                        if rk in self._alloc_info:
                            self._alloc_info[vk] = self._alloc_info[rk]
                        self._record_alias(vk, rk)
                    else:
                        st.pop(vk, None)
            return

        if k == CursorKind.CXX_DELETE_EXPR:
            children = list(node.get_children())
            if children:
                rk = self._ref_key(children[0])
                if rk is not None:
                    self._free_allocation(rk, node, st, children[0].spelling, "delete")
            return

        if k == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2 and self._is_assign(node, children):
                lhs, rhs = children
                lk = self._ref_key(lhs)
                if lk is not None:
                    alloc_result = self._find_alloc_in([rhs])
                    if alloc_result is not None:
                        alloc_node, dealloc_fn, label = alloc_result
                        st[lk] = _RState.ALLOCATED
                        loc = lhs.location
                        self._alloc_info[lk] = (
                            loc.file.name if loc.file else "<unknown>",
                            loc.line, loc.column, lhs.spelling,
                        )
                        self._expected_dealloc[lk] = dealloc_fn
                        self._resource_label[lk]   = label
                    else:
                        rk = self._ref_key(rhs)
                        if rk is not None and rk in st:
                            st[lk] = st[rk]
                            if rk in self._alloc_info:
                                self._alloc_info[lk] = self._alloc_info[rk]
                            self._record_alias(lk, rk)
                        else:
                            st.pop(lk, None)
            else:
                for child in children:
                    self._transfer(child, st)
            return

        if k == CursorKind.CALL_EXPR:
            fn = node.spelling
            args = list(node.get_arguments())

            if fn in _DEALLOC_FUNCS:
                if args:
                    ak = self._ref_key(args[0])
                    if ak is not None and ak in st:
                        self._free_allocation(ak, node, st, args[0].spelling, fn)
                return

            if self.summary_db is not None:
                summary = self.summary_db.lookup(node)
                if summary is not None:
                    for i, arg in enumerate(args):
                        ak = self._ref_key(arg)
                        if ak is None or ak not in st:
                            continue
                        if i in summary.frees_params:
                            self._free_allocation(ak, node, st, arg.spelling, "free")
                        elif i in summary.escapes_params:
                            if st.get(ak) == _RState.ALLOCATED:
                                st[ak] = _RState.ESCAPED
                    return

            for arg in args:
                ak = self._ref_key(arg)
                if ak is not None and st.get(ak) == _RState.ALLOCATED:
                    st[ak] = _RState.ESCAPED
            return

        if k == CursorKind.RETURN_STMT:
            for child in node.get_children():
                rk = self._ref_key(child)
                if rk is not None and st.get(rk) == _RState.ALLOCATED:
                    st[rk] = _RState.ESCAPED
            return

        for child in node.get_children():
            self._transfer(child, st)

    _TRANSPARENT = frozenset({
        CursorKind.UNEXPOSED_EXPR,
        CursorKind.PAREN_EXPR,
        CursorKind.CSTYLE_CAST_EXPR,
    })

    def _find_alloc_in(self, nodes: list) -> tuple | None:
        for node in nodes:
            result = self._find_alloc(node)
            if result is not None:
                return result
        return None

    def _find_alloc(self, node) -> tuple | None:
        if node.kind == CursorKind.CALL_EXPR and node.spelling in _ALLOC_FUNCS:
            fn = node.spelling
            dealloc_fn, label = RESOURCE_REGISTRY[fn]
            return (node, dealloc_fn, label)

        if node.kind == CursorKind.CXX_NEW_EXPR:
            return (node, "delete", "heap memory")

        if node.kind == CursorKind.CALL_EXPR and self.summary_db is not None:
            summary = self.summary_db.lookup(node)
            if summary is not None and summary.returns_alloc:
                return (node, summary.returns_dealloc, "heap memory")

        if node.kind in self._TRANSPARENT:
            for child in node.get_children():
                result = self._find_alloc(child)
                if result is not None:
                    return result
        return None

    def _first_ref_key(self, nodes: list) -> str | None:
        for node in nodes:
            rk = self._ref_key(node)
            if rk is not None:
                return rk
        return None

    def _ref_key(self, expr) -> str | None:
        if expr.kind in self._TRANSPARENT:
            children = list(expr.get_children())
            if children:
                return self._ref_key(children[0])
        if expr.kind == CursorKind.DECL_REF_EXPR:
            ref = expr.referenced
            if ref is not None:
                return ref.get_usr() or f"{ref.spelling}@{ref.location.line}:{ref.location.column}"
            return expr.spelling or None
        return None

    def _var_key(self, decl) -> str:
        return decl.get_usr() or f"{decl.spelling}@{decl.location.line}:{decl.location.column}"

    def _is_assign(self, node, children) -> bool:
        lhs_end   = children[0].extent.end.offset
        rhs_start = children[1].extent.start.offset
        for tok in node.get_tokens():
            if lhs_end <= tok.extent.start.offset < rhs_start and tok.spelling == "=":
                return True
        return False

    def _report_double_free(self, node, var_name: str) -> None:
        loc = node.location
        key = (loc.file.name if loc.file else "<unknown>", loc.line, loc.column)
        if key not in self._reported:
            self._reported.add(key)
            self._issues.append({
                "file": key[0],
                "line": key[1],
                "column": key[2],
                "severity": "ERROR",
                "message": f"Double-free: '{var_name}' may already be freed",
                **_ISSUE_DOUBLE_FREE,
            })

    def _emit(self, file_: str, line: int, col: int, severity: str, msg: str, meta: dict | None = None) -> None:
        key = (file_, line, col, msg)
        if key not in self._reported:
            self._reported.add(key)
            issue = {
                "file": file_,
                "line": line,
                "column": col,
                "severity": severity,
                "message": msg,
            }
            if meta:
                issue.update(meta)
            self._issues.append(issue)