from src.rules.rule import Rule
import clang.cindex as clang


# Functions whose return value may be NULL and therefore must be checked
# before being dereferenced.
NULL_RETURNING_FUNCS = {
    "malloc", "calloc", "realloc",
    "getenv", "fopen", "freopen", "tmpfile",
    "strchr", "strrchr", "strstr",
    "fgets",
}


class NullDereference(Rule):
    """
    Dataflow analysis over the CFG.

    State = set of variable names that are *possibly* null at a given program point.
    - GEN : variables assigned NULL/nullptr/0 or from a null-returning function.
    - KILL: variables that have been null-checked (appear as condition in an if).
    """

    def __init__(self, targetFile=None):
        self.targetFile = targetFile
        self.issues = []

    # ── null-literal / null-source detection ───────────────────────────────

    def _is_null_literal(self, node):
        """True if node is NULL / nullptr / integer literal 0."""
        if node.kind == clang.CursorKind.GNU_NULL_EXPR:
            return True
        if node.kind == clang.CursorKind.CXX_NULL_PTR_LITERAL_EXPR:
            return True
        if node.kind == clang.CursorKind.INTEGER_LITERAL:
            tokens = list(node.get_tokens())
            return len(tokens) == 1 and tokens[0].spelling == "0"
        # Handles macro NULL which expands to __null or 0, and implicit casts.
        if node.kind == clang.CursorKind.UNEXPOSED_EXPR:
            children = list(node.get_children())
            return any(self._is_null_literal(c) for c in children)
        return False

    def _assigned_from_null_func(self, rhs_node):
        """True if rhs is a call to a NULL-returning function."""
        if rhs_node.kind in (clang.CursorKind.CALL_EXPR,
                              clang.CursorKind.UNEXPOSED_EXPR):
            if rhs_node.spelling in NULL_RETURNING_FUNCS:
                return True
            for child in rhs_node.get_children():
                if self._assigned_from_null_func(child):
                    return True
        return False

    def _extract_var_name(self, node):
        """Return spelling of the first DECL_REF_EXPR in the subtree, else None."""
        if node.kind == clang.CursorKind.DECL_REF_EXPR:
            return node.spelling
        for child in node.get_children():
            result = self._extract_var_name(child)
            if result:
                return result
        return None

    def _unwrap(self, node):
        """Skip transparent wrapper nodes (implicit casts, parens) to the inner expr."""
        while node is not None and node.kind in (
            clang.CursorKind.UNEXPOSED_EXPR,
            clang.CursorKind.PAREN_EXPR,
        ):
            children = list(node.get_children())
            if not children:
                return node
            node = children[0]
        return node

    def _operand_var(self, node):
        """If `node` (after unwrapping) is a direct reference to a variable, return its name."""
        node = self._unwrap(node)
        if node is not None and node.kind == clang.CursorKind.DECL_REF_EXPR:
            return node.spelling
        return None

    # ── GEN / KILL for declarations and assignments ────────────────────────

    def _apply_genkill(self, node, null_vars):
        """Update null_vars in-place based on declarations / plain assignments."""
        kind = node.kind

        # `int *p = ...;` arrives as DECL_STMT wrapping one or more VAR_DECLs.
        if kind == clang.CursorKind.DECL_STMT:
            for child in node.get_children():
                self._apply_genkill(child, null_vars)
            return

        if kind == clang.CursorKind.VAR_DECL:
            children = list(node.get_children())
            init = children[-1] if children else None
            if init is not None and (
                self._is_null_literal(init) or self._assigned_from_null_func(init)
            ):
                null_vars.add(node.spelling)
            else:
                null_vars.discard(node.spelling)
            return

        # `lhs = rhs` — only treat as GEN/KILL when the target is a plain variable
        # (NOT a dereference like `*p = ...` or `n->f = ...`).
        if kind == clang.CursorKind.BINARY_OPERATOR:
            op_spellings = [t.spelling for t in node.get_tokens()]
            if "=" in op_spellings:
                children = list(node.get_children())
                if len(children) == 2:
                    lhs, rhs = children
                    var = self._operand_var(lhs)
                    if var:
                        if self._is_null_literal(rhs) or self._assigned_from_null_func(rhs):
                            null_vars.add(var)
                        else:
                            null_vars.discard(var)

    # ── dereference detection ──────────────────────────────────────────────

    def _pointer_operand(self, node):
        """Return the node being dereferenced by a deref expression, else None."""
        kind = node.kind
        children = list(node.get_children())

        if kind == clang.CursorKind.UNARY_OPERATOR:
            toks = [t.spelling for t in node.get_tokens()]
            if toks and toks[0] == "*" and children:
                return children[0]
            return None

        if kind in (clang.CursorKind.MEMBER_REF_EXPR,
                    clang.CursorKind.ARRAY_SUBSCRIPT_EXPR):
            # The object/array being dereferenced is the first child.
            return children[0] if children else None

        return None

    def _make_issue(self, var, node):
        loc = node.location
        file_obj = loc.file
        file_name = file_obj.name if file_obj else "<unknown>"

        # Skip issues from headers / system files when a target file is set.
        if self.targetFile and file_name != self.targetFile:
            return None

        return {
            "file": file_name,
            "line": loc.line,
            "column": loc.column,
            "severity": "ERROR",
            "message": (
                f"Potential null pointer dereference of '{var}' "
                f"— check for NULL before use"
            ),
        }

    def _find_derefs(self, node, null_vars, new_issues):
        """Recursively scan a statement subtree for dereferences of possibly-null vars."""
        operand = self._pointer_operand(node)
        if operand is not None:
            var = self._operand_var(operand)
            if var and var in null_vars:
                issue = self._make_issue(var, node)
                if issue is not None:
                    new_issues.append(issue)

        for child in node.get_children():
            self._find_derefs(child, null_vars, new_issues)

    def _process_stmt(self, node, null_vars):
        """
        Detect dereferences in `node`, then update null_vars for this statement.
        Returns list of new issues found.
        """
        new_issues = []
        # Reads (dereferences) happen at the current state, before any
        # reassignment performed by this same statement.
        self._find_derefs(node, null_vars, new_issues)
        self._apply_genkill(node, null_vars)
        return new_issues

    # ── null-check detection (for KILL sets) ──────────────────────────────

    def _vars_checked_in_condition(self, cond_node):
        """
        Returns (null_confirmed, null_cleared):
        - null_confirmed: vars proven null in the THEN branch (== nullptr)
        - null_cleared:   vars proven non-null in the THEN branch (!= nullptr / if(ptr))
        """
        null_confirmed = set()
        null_cleared = set()
        if cond_node is None:
            return null_confirmed, null_cleared

        kind = cond_node.kind

        if kind == clang.CursorKind.BINARY_OPERATOR:
            toks = [t.spelling for t in cond_node.get_tokens()]
            children = list(cond_node.get_children())
            vars_in_cond = set()
            for child in children:
                var = self._extract_var_name(child)
                if var:
                    vars_in_cond.add(var)

            if "!=" in toks:
                null_cleared |= vars_in_cond   # ptr != NULL → safe in then-branch
            elif "==" in toks:
                null_confirmed |= vars_in_cond  # ptr == NULL → still null in then-branch

        elif kind == clang.CursorKind.UNARY_OPERATOR:
            toks = [t.spelling for t in cond_node.get_tokens()]
            if toks and toks[0] == "!":
                for child in cond_node.get_children():
                    var = self._extract_var_name(child)
                    if var:
                        null_cleared.add(var)  # !ptr → ptr is null, then-branch is "null path"

        elif kind == clang.CursorKind.DECL_REF_EXPR:
            null_cleared.add(cond_node.spelling)  # if(ptr) → non-null in then-branch

        return null_confirmed, null_cleared

    # ── dataflow driver ────────────────────────────────────────────────────

    def check(self, cfg):
        """Run the full CFG + dataflow analysis on one function."""
        self.issues = []
        all_blocks = cfg.blocks

        in_state = {b.id: set() for b in all_blocks}
        out_state = {b.id: set() for b in all_blocks}

        worklist = list(all_blocks)

        while worklist:
            block = worklist.pop(0)

            # IN[B] = union of OUT[P] for all predecessors P
            merged = set()
            for pred in block.preds:
                merged |= out_state[pred.id]
            in_state[block.id] = merged

            null_vars = set(merged)  # working copy

            for stmt in block.stmts:
                # If this stmt is an if-condition, apply KILL before body
                null_confirmed, null_cleared = self._vars_checked_in_condition(stmt)
                null_vars -= null_cleared
                null_vars |= null_confirmed

                issues = self._process_stmt(stmt, null_vars)
                self.issues.extend(issues)

            new_out = set(null_vars)
            if new_out != out_state[block.id]:
                out_state[block.id] = new_out
                for succ in block.succs:
                    if succ not in worklist:
                        worklist.append(succ)

        return self.issues
