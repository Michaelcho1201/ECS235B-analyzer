from dataclasses import dataclass, field

from collections import defaultdict


class SymbolicResult:
    def __init__(self, states):
        self.states = states
        self.states_by_block = defaultdict(list)

        for state in states:
            self.states_by_block[state.block_id].append(state)

    def conditions_for_block(self, block_id):
        return [
            state.path_conditions
            for state in self.states_by_block.get(block_id, [])
        ]
@dataclass
class SymbolicState:
    block_id: int
    path_conditions: list[str] = field(default_factory=list)
    visited: dict[int, int] = field(default_factory=dict)


class SymbolicExecutor:
    def __init__(self, max_visits_per_block=2, max_states=200):
        self.max_visits_per_block = max_visits_per_block
        self.max_states = max_states

    def explore(self, cfg):
        states = []
        worklist = [SymbolicState(cfg.entry.id)]

        block_map = {b.id: b for b in cfg.blocks}

        while worklist:
            if len(states) >= self.max_states:
                break

            state = worklist.pop()
            block = block_map[state.block_id]

            states.append(state)

            visits = state.visited.get(block.id, 0)
            if visits >= self.max_visits_per_block:
                continue

            new_visited = dict(state.visited)
            new_visited[block.id] = visits + 1

            for succ in block.succs:
                condition = block.edge_conditions.get(succ.id)

                new_conditions = list(state.path_conditions)
                if condition:
                    new_conditions.append(condition)

                worklist.append(SymbolicState(
                    block_id=succ.id,
                    path_conditions=new_conditions,
                    visited=new_visited,
                ))

        return SymbolicResult(states)