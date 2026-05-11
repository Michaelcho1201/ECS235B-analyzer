from collections import deque
from clang.cindex import CursorKind
from src.rules.rule import Rule


class UninitializedVarRule(Rule):
    """
    Forward dataflow analysis: detect variables used before being initialized.

    GEN[b]  = variables declared without an initializer in block b
    KILL[b] = variables declared with an initializer in block b
    IN[b]   = union of OUT[pred] for all predecessors
    OUT[b]  = (IN[b] - KILL[b]) | GEN[b]

    After fixpoint, walk each reachable block in statement order and flag any
    DECL_REF_EXPR whose name is in the possibly-uninitialized set at that point.
    """

    def check(self, cfg) -> list[dict]:
        blocks = cfg.blocks

        gen = {b.id: set() for b in blocks}
        kill = {b.id: set() for b in blocks}
        for b in blocks:
            for stmt in b.stmts:
                self._compute_gen_kill(stmt, gen[b.id], kill[b.id])

        # Worklist: forward may-be-uninitialized analysis
        out = {b.id: set() for b in blocks}
        in_ = {b.id: set() for b in blocks}
        worklist = deque([cfg.entry])

        while worklist:
            block = worklist.popleft()
            new_in = set()
            for pred in block.preds:
                new_in |= out[pred.id]
            in_[block.id] = new_in

            new_out = (new_in - kill[block.id]) | gen[block.id]
            if new_out != out[block.id]:
                out[block.id] = new_out
                worklist.extend(block.succs)

        issues = []
        reported = set()
        for block in cfg.reachable_blocks():
            current_uninit = set(in_[block.id])
            for stmt in block.stmts:
                self._find_uses(stmt, current_uninit, issues, reported)
                self._update_uninit(stmt, current_uninit)

        return issues

    def _compute_gen_kill(self, node, gen, kill):
        if node.kind == CursorKind.VAR_DECL:
            children = list(node.get_children())
            if children:
                kill.add(node.spelling)
            else:
                gen.add(node.spelling)
            return
        for child in node.get_children():
            self._compute_gen_kill(child, gen, kill)

    def _find_uses(self, node, uninit_set, issues, reported):
        # For simple assignments (x = ...), skip flagging the LHS
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2 and self._is_plain_assignment(node, children):
                self._find_uses(children[1], uninit_set, issues, reported)
                return

        if node.kind == CursorKind.DECL_REF_EXPR:
            name = node.spelling
            if name in uninit_set:
                key = (name, node.location.line, node.location.column)
                if key not in reported:
                    reported.add(key)
                    loc = node.location
                    issues.append({
                        "file": loc.file.name if loc.file else "<unknown>",
                        "line": loc.line,
                        "column": loc.column,
                        "severity": "WARNING",
                        "message": f"Variable '{name}' may be used uninitialized",
                    })
            return

        for child in node.get_children():
            self._find_uses(child, uninit_set, issues, reported)

    def _update_uninit(self, node, uninit_set):
        """Update the uninitialized set after processing a statement."""
        if node.kind == CursorKind.VAR_DECL:
            children = list(node.get_children())
            if children:
                uninit_set.discard(node.spelling)
            else:
                uninit_set.add(node.spelling)
            return
        # Simple assignment kills the LHS variable
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2 and self._is_plain_assignment(node, children):
                lhs = children[0]
                if lhs.kind == CursorKind.DECL_REF_EXPR:
                    uninit_set.discard(lhs.spelling)
                return
        for child in node.get_children():
            self._update_uninit(child, uninit_set)

    def _is_plain_assignment(self, node, children):
        """Return True if this BINARY_OPERATOR is a plain '=' assignment."""
        lhs_end = children[0].extent.end.offset
        rhs_start = children[1].extent.start.offset
        for tok in node.get_tokens():
            tok_start = tok.extent.start.offset
            if lhs_end <= tok_start < rhs_start and tok.spelling == "=":
                return True
        return False
