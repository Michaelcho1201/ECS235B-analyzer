from __future__ import annotations

from dataclasses import dataclass, field
from clang.cindex import CursorKind


_TRANSPARENT = frozenset({
    CursorKind.UNEXPOSED_EXPR,
    CursorKind.PAREN_EXPR,
    CursorKind.CSTYLE_CAST_EXPR,
})


@dataclass
class FunctionSummary:
    returns_alloc:   bool      = False
    returns_dealloc: str       = "free"
    frees_params:    set[int]  = field(default_factory=set)
    escapes_params:  set[int]  = field(default_factory=set)


class SummaryDatabase:

    def __init__(self) -> None:
        self._db: dict[str, FunctionSummary] = {}

    def add(self, func_cursor, summary: FunctionSummary) -> None:
        usr = func_cursor.get_usr()
        if usr:
            self._db[usr] = summary

    def lookup(self, call_expr) -> FunctionSummary | None:
        ref = self._find_callee_decl(call_expr)
        if ref is None:
            return None
        usr = ref.get_usr()
        return self._db.get(usr) if usr else None

    @staticmethod
    def _find_callee_decl(node, depth: int = 0):
        if depth > 3:
            return None
        if node.kind == CursorKind.DECL_REF_EXPR:
            return node.referenced
        for child in node.get_children():
            result = SummaryDatabase._find_callee_decl(child, depth + 1)
            if result is not None:
                return result
        return None


class SummaryBuilder:

    def __init__(self, alloc_funcs: frozenset[str], dealloc_funcs: frozenset[str], dealloc_for: dict[str, str]) -> None:
        self._alloc_funcs   = alloc_funcs
        self._dealloc_funcs = dealloc_funcs
        self._dealloc_for   = dealloc_for

    def build(self, func_cursor, cfg) -> FunctionSummary:
        summary = FunctionSummary()

        param_usr_to_idx: dict[str, int] = {}
        idx = 0
        for child in func_cursor.get_children():
            if child.kind == CursorKind.PARM_DECL:
                usr = child.get_usr()
                if usr:
                    param_usr_to_idx[usr] = idx
                idx += 1

        for block in cfg.reachable_blocks():
            for stmt in block.stmts:
                self._scan(stmt, summary, param_usr_to_idx)

        return summary

    def _scan(self, node, summary: FunctionSummary, param_idx: dict[str, int]) -> None:
        k = node.kind

        if k == CursorKind.RETURN_STMT:
            for child in node.get_children():
                alloc_fn = self._find_alloc_call(child)
                if alloc_fn:
                    summary.returns_alloc   = True
                    summary.returns_dealloc = self._dealloc_for.get(alloc_fn, "free")

        if k == CursorKind.CALL_EXPR and node.spelling in self._dealloc_funcs:
            args = list(node.get_arguments())
            if args:
                usr = self._decl_ref_usr(args[0])
                if usr and usr in param_idx:
                    summary.frees_params.add(param_idx[usr])

        for child in node.get_children():
            self._scan(child, summary, param_idx)

    def _find_alloc_call(self, node) -> str | None:
        if node.kind == CursorKind.CALL_EXPR and node.spelling in self._alloc_funcs:
            return node.spelling
        if node.kind in _TRANSPARENT:
            for child in node.get_children():
                result = self._find_alloc_call(child)
                if result:
                    return result
        return None

    def _decl_ref_usr(self, expr) -> str | None:
        if expr.kind in _TRANSPARENT:
            children = list(expr.get_children())
            return self._decl_ref_usr(children[0]) if children else None
        if expr.kind == CursorKind.DECL_REF_EXPR:
            ref = expr.referenced
            return ref.get_usr() if ref else None
        return None
