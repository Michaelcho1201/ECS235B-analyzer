from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass

from clang.cindex import CursorKind, TypeKind

from src.rules.rule import Rule


@dataclass(frozen=True)
class _LoopBound:
    var_key: str
    var_name: str
    upper_exclusive: int


class BufferOverflowRule(Rule):
    """
    Detect probable buffer overflows using lightweight intra-procedural analysis.

    Current coverage:
    - Fixed-size array index out-of-bounds (constant indices and simple loop indices).
    - Unsafe copy/write APIs when destination capacity is known.
    """

    _COPY_FUNCS = {"strcpy", "strcat", "sprintf", "vsprintf", "gets"}
    _MEM_FUNCS = {"memcpy", "memmove"}
    _SCAN_FUNCS = {"scanf", "sscanf", "fscanf"}

    def check(self, cfg) -> list[dict]:
        self._issues: list[dict] = []
        self._reported: set[tuple[str, int, int, str]] = set()
        self._array_capacity: dict[str, int] = {}
        self._known_string_len: dict[str, int] = {}

        reachable = cfg.reachable_blocks()
        for block in reachable:
            for stmt in block.stmts:
                self._collect_array_facts(stmt)

        loop_bounds_by_block = self._infer_loop_bounds(cfg)
        for block in reachable:
            loop_bounds = loop_bounds_by_block.get(block.id, {})
            for stmt in block.stmts:
                self._check_array_subscripts(stmt, loop_bounds)
                self._check_dangerous_calls(stmt)

        return self._issues

    def _collect_array_facts(self, node):
        if node.kind == CursorKind.VAR_DECL:
            var_key, _ = self._decl_key_and_name(node)
            t = node.type
            if t.kind == TypeKind.CONSTANTARRAY and var_key:
                try:
                    cap = int(t.element_count)
                except Exception:
                    cap = 0
                if cap > 0:
                    self._array_capacity[var_key] = cap

                    init_len = self._string_initializer_len(node)
                    if init_len is not None:
                        # Best effort model for current C-string length in a fixed buffer.
                        self._known_string_len[var_key] = min(init_len, max(0, cap - 1))

        for child in node.get_children():
            self._collect_array_facts(child)

    def _infer_loop_bounds(self, cfg) -> dict[int, dict[str, int]]:
        """
        Propagate simple loop upper-bounds to loop-body blocks.

        We parse conditions like `i < N` / `i <= N` from condition blocks and
        carry the bound into the successor that can flow back to that condition.
        """
        block_map = {b.id: b for b in cfg.blocks}
        loop_bounds_by_block: dict[int, dict[str, int]] = {b.id: {} for b in cfg.blocks}

        for block in cfg.blocks:
            parsed = None
            for stmt in block.stmts:
                parsed = self._parse_upper_bound(stmt)
                if parsed is not None:
                    break
            if parsed is None or not block.succs:
                continue

            loop_succ = self._find_loop_successor(block, block_map)
            if loop_succ is None:
                continue

            queue = deque([loop_succ])
            visited: set[int] = set()
            while queue:
                cur = queue.popleft()
                if cur.id in visited:
                    continue
                visited.add(cur.id)
                loop_bounds_by_block[cur.id][parsed.var_key] = parsed.upper_exclusive
                for succ in cur.succs:
                    # Do not keep re-entering the condition node; we only need body context.
                    if succ.id != block.id:
                        queue.append(succ)

        return loop_bounds_by_block

    def _find_loop_successor(self, condition_block, block_map) -> object | None:
        for succ in condition_block.succs:
            if self._reaches_block(succ, condition_block.id, block_map):
                return succ
        return None

    def _reaches_block(self, start, target_id: int, block_map) -> bool:
        queue = deque([start])
        seen: set[int] = set()
        while queue:
            block = queue.popleft()
            if block.id in seen:
                continue
            if block.id == target_id:
                return True
            seen.add(block.id)
            for succ in block.succs:
                if succ.id not in seen and succ.id in block_map:
                    queue.append(succ)
        return False

    def _parse_upper_bound(self, node) -> _LoopBound | None:
        if node.kind != CursorKind.BINARY_OPERATOR:
            return None

        children = list(node.get_children())
        if len(children) != 2:
            return None

        lhs, rhs = children
        op = self._binary_operator(node, lhs, rhs)
        if op not in {"<", "<="}:
            return None

        lhs_ref = self._decl_ref_key_and_name(lhs)
        rhs_const = self._const_int(rhs)
        if lhs_ref is None or rhs_const is None:
            return None

        var_key, var_name = lhs_ref
        upper = rhs_const if op == "<" else rhs_const + 1
        return _LoopBound(var_key=var_key, var_name=var_name, upper_exclusive=upper)

    def _check_array_subscripts(self, node, loop_bounds: dict[str, int]):
        if node.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
            children = list(node.get_children())
            if len(children) >= 2:
                base = children[0]
                idx = children[1]
                base_ref = self._decl_ref_key_and_name(base)
                if base_ref is not None:
                    base_key, base_name = base_ref
                    capacity = self._array_capacity.get(base_key)
                    if capacity is not None:
                        const_idx = self._const_int(idx)
                        if const_idx is not None and const_idx >= capacity:
                            self._report(
                                node,
                                "ERROR",
                                f"Buffer overflow: index {const_idx} is out of bounds for "
                                f"'{base_name}' (size {capacity})",
                            )
                        else:
                            idx_bound = self._index_upper_bound(idx, loop_bounds)
                            if idx_bound is not None and idx_bound >= capacity:
                                self._report(
                                    node,
                                    "ERROR",
                                    f"Buffer overflow: index on '{base_name}' can reach "
                                    f"{idx_bound} (size {capacity})",
                                )

        for child in node.get_children():
            self._check_array_subscripts(child, loop_bounds)

    def _index_upper_bound(self, idx, loop_bounds: dict[str, int]) -> int | None:
        const_idx = self._const_int(idx)
        if const_idx is not None:
            return const_idx

        ref = self._decl_ref_key_and_name(idx)
        if ref is not None:
            key, _ = ref
            upper = loop_bounds.get(key)
            if upper is not None:
                return upper - 1

        if idx.kind == CursorKind.BINARY_OPERATOR:
            children = list(idx.get_children())
            if len(children) == 2:
                lhs, rhs = children
                op = self._binary_operator(idx, lhs, rhs)
                if op in {"+", "-"}:
                    lhs_bound = self._index_upper_bound(lhs, loop_bounds)
                    rhs_bound = self._index_upper_bound(rhs, loop_bounds)
                    if lhs_bound is not None and rhs_bound is not None:
                        return lhs_bound + rhs_bound if op == "+" else lhs_bound - rhs_bound

        return None

    def _check_dangerous_calls(self, node):
        if node.kind == CursorKind.CALL_EXPR:
            fn = node.spelling
            args = list(node.get_arguments())
            if fn in self._COPY_FUNCS:
                self._check_copy_call(node, fn, args)
            elif fn in self._MEM_FUNCS:
                self._check_mem_call(node, fn, args)
            elif fn in self._SCAN_FUNCS:
                self._check_scan_call(node, fn, args)

        for child in node.get_children():
            self._check_dangerous_calls(child)

    def _check_copy_call(self, node, fn: str, args):
        if fn == "gets":
            if args:
                dst = self._decl_ref_key_and_name(args[0])
                if dst is not None:
                    dst_key, dst_name = dst
                    cap = self._array_capacity.get(dst_key)
                    if cap is not None:
                        self._report(
                            node,
                            "ERROR",
                            f"Unbounded write: gets() can overflow '{dst_name}' (size {cap})",
                        )
            return

        if not args:
            return

        dst_ref = self._decl_ref_key_and_name(args[0])
        if dst_ref is None:
            return

        dst_key, dst_name = dst_ref
        dst_cap = self._array_capacity.get(dst_key)
        if dst_cap is None:
            return

        if fn == "strcpy":
            if len(args) < 2:
                return
            src_len = self._cstring_len(args[1])
            if src_len is None:
                self._report(
                    node,
                    "WARNING",
                    f"Potential overflow: strcpy() writes to '{dst_name}' (size {dst_cap}) "
                    "with unknown source length",
                )
                return

            required = src_len + 1
            if required > dst_cap:
                self._report(
                    node,
                    "ERROR",
                    f"Buffer overflow: strcpy() may write {required} bytes into "
                    f"'{dst_name}' (size {dst_cap})",
                )
            return

        if fn == "strcat":
            if len(args) < 2:
                return
            dst_len = self._known_string_len.get(dst_key)
            src_len = self._cstring_len(args[1])
            if dst_len is None or src_len is None:
                self._report(
                    node,
                    "WARNING",
                    f"Potential overflow: strcat() appends to '{dst_name}' (size {dst_cap}) "
                    "with unknown string length",
                )
                return

            required = dst_len + src_len + 1
            if required > dst_cap:
                self._report(
                    node,
                    "ERROR",
                    f"Buffer overflow: strcat() may write {required} bytes into "
                    f"'{dst_name}' (size {dst_cap})",
                )
            return

        if fn in {"sprintf", "vsprintf"}:
            self._report(
                node,
                "WARNING",
                f"Potential overflow: {fn}() writes formatted output to '{dst_name}' "
                f"(size {dst_cap}) without a size bound",
            )

    def _check_mem_call(self, node, fn: str, args):
        if len(args) < 3:
            return

        dst_ref = self._decl_ref_key_and_name(args[0])
        if dst_ref is None:
            return

        dst_key, dst_name = dst_ref
        dst_cap = self._array_capacity.get(dst_key)
        if dst_cap is None:
            return

        write_size = self._const_int(args[2])
        if write_size is None:
            self._report(
                node,
                "WARNING",
                f"Potential overflow: {fn}() writes unknown byte count into "
                f"'{dst_name}' (size {dst_cap})",
            )
            return

        if write_size > dst_cap:
            self._report(
                node,
                "ERROR",
                f"Buffer overflow: {fn}() writes {write_size} bytes into "
                f"'{dst_name}' (size {dst_cap})",
            )

    def _check_scan_call(self, node, fn: str, args):
        if len(args) < 2:
            return

        # scanf(format, ...)
        # sscanf(input, format, ...)
        # fscanf(file, format, ...)
        format_index = 0 if fn == "scanf" else 1
        format_expr = args[format_index]
        fmt = self._string_literal_value(format_expr)
        if fmt is None:
            return

        specs = self._extract_scan_specs(fmt)
        if not specs:
            return

        data_arg_index = format_index + 1
        for spec_pos, width in specs:
            arg_pos = data_arg_index + spec_pos
            if arg_pos >= len(args):
                break
            dst_ref = self._decl_ref_key_and_name(args[arg_pos])
            if dst_ref is None:
                continue

            dst_key, dst_name = dst_ref
            dst_cap = self._array_capacity.get(dst_key)
            if dst_cap is None:
                continue

            if width is None:
                self._report(
                    node,
                    "WARNING",
                    f"Potential overflow: {fn}() reads unbounded %s into "
                    f"'{dst_name}' (size {dst_cap})",
                )
            elif width + 1 > dst_cap:
                self._report(
                    node,
                    "ERROR",
                    f"Buffer overflow: {fn}() width %{width}s exceeds '{dst_name}' "
                    f"capacity {dst_cap}",
                )

    def _extract_scan_specs(self, fmt: str) -> list[tuple[int, int | None]]:
        """
        Return positions of %s-like conversions and their width.
        Each item is (string_spec_index, width_or_none).
        """
        specs: list[tuple[int, int | None]] = []
        i = 0
        str_idx = 0
        while i < len(fmt):
            if fmt[i] != "%":
                i += 1
                continue
            if i + 1 < len(fmt) and fmt[i + 1] == "%":
                i += 2
                continue
            i += 1
            suppress = i < len(fmt) and fmt[i] == "*"
            if suppress:
                i += 1

            width_start = i
            while i < len(fmt) and fmt[i].isdigit():
                i += 1
            width_text = fmt[width_start:i]
            width = int(width_text) if width_text else None

            # Skip common length modifiers.
            if i < len(fmt) and fmt[i] in {"h", "l", "j", "z", "t", "L"}:
                if fmt[i] in {"h", "l"} and i + 1 < len(fmt) and fmt[i + 1] == fmt[i]:
                    i += 2
                else:
                    i += 1

            if i >= len(fmt):
                break

            conv = fmt[i]
            i += 1
            if conv == "s" and not suppress:
                specs.append((str_idx, width))
                str_idx += 1
            elif conv not in {"n"} and not suppress:
                str_idx += 1
        return specs

    def _cstring_len(self, expr) -> int | None:
        lit = self._string_literal_value(expr)
        if lit is not None:
            return len(lit)

        ref = self._decl_ref_key_and_name(expr)
        if ref is not None:
            key, _ = ref
            return self._known_string_len.get(key)
        return None

    def _string_initializer_len(self, decl) -> int | None:
        for child in decl.get_children():
            lit = self._string_literal_value(child)
            if lit is not None:
                return len(lit)
        return None

    def _string_literal_value(self, expr) -> str | None:
        if expr.kind == CursorKind.STRING_LITERAL:
            tokens = list(expr.get_tokens())
            if not tokens:
                return None
            text = "".join(tok.spelling for tok in tokens)
            # Keep it simple: decode plain quoted strings.
            if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
                body = text[1:-1]
                return bytes(body, "utf-8").decode("unicode_escape")
            return text.strip('"')

        for child in expr.get_children():
            lit = self._string_literal_value(child)
            if lit is not None:
                return lit
        return None

    def _decl_key_and_name(self, decl) -> tuple[str | None, str]:
        if decl is None:
            return None, "<unknown>"
        key = decl.get_usr() or f"{decl.spelling}@{decl.location.line}:{decl.location.column}"
        return key, decl.spelling or "<unknown>"

    def _decl_ref_key_and_name(self, expr) -> tuple[str, str] | None:
        if expr.kind == CursorKind.UNEXPOSED_EXPR or expr.kind == CursorKind.PAREN_EXPR:
            children = list(expr.get_children())
            if children:
                return self._decl_ref_key_and_name(children[0])
            return None

        if expr.kind == CursorKind.DECL_REF_EXPR:
            ref = expr.referenced
            if ref is None:
                key = expr.spelling
                return (key, expr.spelling) if key else None
            key, name = self._decl_key_and_name(ref)
            return (key, name) if key else None

        if expr.kind == CursorKind.ARRAY_SUBSCRIPT_EXPR:
            children = list(expr.get_children())
            if children:
                return self._decl_ref_key_and_name(children[0])

        return None

    def _const_int(self, expr) -> int | None:
        if expr.kind == CursorKind.UNEXPOSED_EXPR or expr.kind == CursorKind.PAREN_EXPR:
            children = list(expr.get_children())
            if len(children) == 1:
                return self._const_int(children[0])

        if expr.kind == CursorKind.INTEGER_LITERAL:
            token_text = "".join(tok.spelling for tok in expr.get_tokens()).strip()
            return self._parse_int_token(token_text)

        if expr.kind == CursorKind.UNARY_OPERATOR:
            tokens = [tok.spelling for tok in expr.get_tokens()]
            children = list(expr.get_children())
            if tokens and tokens[0] == "-" and children:
                inner = self._const_int(children[0])
                return -inner if inner is not None else None

        return None

    def _parse_int_token(self, text: str) -> int | None:
        if not text:
            return None
        clean = re.sub(r"[uUlL]+$", "", text)
        try:
            return int(clean, 0)
        except ValueError:
            return None

    def _binary_operator(self, node, lhs, rhs) -> str | None:
        lhs_end = lhs.extent.end.offset
        rhs_start = rhs.extent.start.offset
        parts = []
        for tok in node.get_tokens():
            tok_start = tok.extent.start.offset
            if lhs_end <= tok_start < rhs_start:
                parts.append(tok.spelling)
        op = "".join(parts).strip()
        return op or None

    def _report(self, node, severity: str, message: str):
        loc = node.location
        line = loc.line
        col = loc.column
        file_name = loc.file.name if loc.file else "<unknown>"
        key = (file_name, line, col, message)
        if key in self._reported:
            return
        self._reported.add(key)
        self._issues.append({
            "file": file_name,
            "line": line,
            "column": col,
            "severity": severity,
            "message": message,
        })
