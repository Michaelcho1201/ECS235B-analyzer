from collections import deque
from clang.cindex import CursorKind


class BasicBlock:
    def __init__(self, block_id):
        self.id = block_id
        self.stmts = []
        self.succs = []
        self.preds = []
        self.edge_conditions = {}  # successor block id -> condition string or None

    def __repr__(self):
        return f"BB{self.id}(stmts={len(self.stmts)}, succs={[b.id for b in self.succs]})"


class CFG:
    def __init__(self, entry, exit_block, blocks):
        self.entry = entry
        self.exit_block = exit_block
        self.blocks = blocks

    def reachable_blocks(self):
        visited = set()
        queue = deque([self.entry])

        while queue:
            block = queue.popleft()

            if block.id in visited:
                continue

            visited.add(block.id)
            queue.extend(block.succs)

        return [b for b in self.blocks if b.id in visited]


class CFGBuilder:
    def __init__(self):
        self._id = 0

    def _new_block(self):
        block = BasicBlock(self._id)
        self._id += 1
        return block

    def _expr_text(self, node):
        return " ".join(t.spelling for t in node.get_tokens())

    def _link(self, a, b, condition=None):
        if b not in a.succs:
            a.succs.append(b)

        if a not in b.preds:
            b.preds.append(a)

        a.edge_conditions[b.id] = condition

    def build(self, func_cursor) -> CFG:
        self._id = 0

        entry = self._new_block()
        exit_block = self._new_block()
        all_blocks = [entry, exit_block]

        body = next(
            (
                c for c in func_cursor.get_children()
                if c.kind == CursorKind.COMPOUND_STMT
            ),
            None,
        )

        if body is None:
            self._link(entry, exit_block)
        else:
            end = self._visit_compound(
                body,
                entry,
                exit_block,
                exit_block,
                exit_block,
                all_blocks,
            )

            if exit_block not in end.succs:
                self._link(end, exit_block)

        return CFG(entry, exit_block, all_blocks)

    def _visit_compound(
        self,
        node,
        current,
        exit_block,
        break_target,
        continue_target,
        blocks,
    ):
        for child in node.get_children():
            current = self._visit_stmt(
                child,
                current,
                exit_block,
                break_target,
                continue_target,
                blocks,
            )

        return current

    def _visit_stmt(
        self,
        node,
        current,
        exit_block,
        break_target,
        continue_target,
        blocks,
    ):
        k = node.kind

        if k == CursorKind.IF_STMT:
            return self._visit_if(
                node,
                current,
                exit_block,
                break_target,
                continue_target,
                blocks,
            )

        elif k == CursorKind.WHILE_STMT:
            return self._visit_while(
                node,
                current,
                exit_block,
                blocks,
            )

        elif k == CursorKind.FOR_STMT:
            return self._visit_for(
                node,
                current,
                exit_block,
                blocks,
            )

        elif k == CursorKind.DO_STMT:
            return self._visit_do(
                node,
                current,
                exit_block,
                blocks,
            )

        elif k == CursorKind.RETURN_STMT:
            current.stmts.append(node)
            self._link(current, exit_block)

            dead = self._new_block()
            blocks.append(dead)
            return dead

        elif k == CursorKind.BREAK_STMT:
            self._link(current, break_target)

            dead = self._new_block()
            blocks.append(dead)
            return dead

        elif k == CursorKind.CONTINUE_STMT:
            self._link(current, continue_target)

            dead = self._new_block()
            blocks.append(dead)
            return dead

        elif k == CursorKind.COMPOUND_STMT:
            return self._visit_compound(
                node,
                current,
                exit_block,
                break_target,
                continue_target,
                blocks,
            )

        else:
            current.stmts.append(node)
            return current

    def _visit_if(
        self,
        node,
        current,
        exit_block,
        break_target,
        continue_target,
        blocks,
    ):
        children = list(node.get_children())

        if not children:
            return current

        condition = children[0]
        then_branch = children[1] if len(children) > 1 else None
        else_branch = children[2] if len(children) > 2 else None

        current.stmts.append(condition)
        cond_text = self._expr_text(condition)

        merge = self._new_block()
        then_block = self._new_block()
        blocks.extend([merge, then_block])

        self._link(current, then_block, cond_text)

        if then_branch is not None:
            then_end = self._visit_stmt(
                then_branch,
                then_block,
                exit_block,
                break_target,
                continue_target,
                blocks,
            )
        else:
            then_end = then_block

        if exit_block not in then_end.succs:
            self._link(then_end, merge)

        if else_branch is not None:
            else_block = self._new_block()
            blocks.append(else_block)

            self._link(current, else_block, f"!({cond_text})")

            else_end = self._visit_stmt(
                else_branch,
                else_block,
                exit_block,
                break_target,
                continue_target,
                blocks,
            )

            if exit_block not in else_end.succs:
                self._link(else_end, merge)

        else:
            self._link(current, merge, f"!({cond_text})")

        return merge

    def _visit_while(self, node, current, exit_block, blocks):
        children = list(node.get_children())

        cond_block = self._new_block()
        body_block = self._new_block()
        after_block = self._new_block()
        blocks.extend([cond_block, body_block, after_block])

        self._link(current, cond_block)

        if children:
            condition = children[0]
            cond_block.stmts.append(condition)
            cond_text = self._expr_text(condition)
        else:
            cond_text = None

        self._link(cond_block, body_block, cond_text)
        self._link(
            cond_block,
            after_block,
            f"!({cond_text})" if cond_text else None,
        )

        body = children[1] if len(children) > 1 else None

        if body is not None:
            body_end = self._visit_stmt(
                body,
                body_block,
                exit_block,
                after_block,
                cond_block,
                blocks,
            )
        else:
            body_end = body_block

        self._link(body_end, cond_block)

        return after_block

    def _visit_for(self, node, current, exit_block, blocks):
        children = list(node.get_children())

        if not children:
            return current

        body = children[-1]
        pre_stmts = children[:-1]

        cond_block = self._new_block()
        body_block = self._new_block()
        inc_block = self._new_block()
        after_block = self._new_block()
        blocks.extend([cond_block, body_block, inc_block, after_block])

        if pre_stmts:
            current.stmts.append(pre_stmts[0])

        for stmt in pre_stmts[1:]:
            cond_block.stmts.append(stmt)

        self._link(current, cond_block)

        cond_text = self._expr_text(pre_stmts[1]) if len(pre_stmts) > 1 else None

        self._link(cond_block, body_block, cond_text)
        self._link(
            cond_block,
            after_block,
            f"!({cond_text})" if cond_text else None,
        )

        body_end = self._visit_stmt(
            body,
            body_block,
            exit_block,
            after_block,
            inc_block,
            blocks,
        )

        self._link(body_end, inc_block)
        self._link(inc_block, cond_block)

        return after_block

    def _visit_do(self, node, current, exit_block, blocks):
        children = list(node.get_children())

        body_block = self._new_block()
        cond_block = self._new_block()
        after_block = self._new_block()
        blocks.extend([body_block, cond_block, after_block])

        self._link(current, body_block)

        body = children[0] if children else None

        if body is not None:
            body_end = self._visit_stmt(
                body,
                body_block,
                exit_block,
                after_block,
                cond_block,
                blocks,
            )
        else:
            body_end = body_block

        self._link(body_end, cond_block)

        if len(children) > 1:
            condition = children[1]
            cond_block.stmts.append(condition)
            cond_text = self._expr_text(condition)
        else:
            cond_text = None

        self._link(cond_block, body_block, cond_text)
        self._link(
            cond_block,
            after_block,
            f"!({cond_text})" if cond_text else None,
        )

        return after_block
