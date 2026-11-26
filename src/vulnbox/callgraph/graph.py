"""Unified provenance-tagged hybrid call graph data structure and query helpers."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable

from vulnbox.models import (
    CallEdge,
    CallGraphSummary,
    CallNode,
    EdgeProvenance,
    UnresolvedCallSite,
)

_PROVENANCE_RANK: dict[EdgeProvenance, int] = {
    "unresolved": 0,
    "static_exact": 1,
    "framework_introspected": 2,
    "runtime_observed": 3,
}


class CallGraph:
    """In-memory directed call graph combining static, framework, and runtime edges."""

    def __init__(self) -> None:
        self.nodes: dict[str, CallNode] = {}
        self._edge_map: dict[tuple[str, str], CallEdge] = {}
        self.unresolved_sites: list[UnresolvedCallSite] = []
        self.runtime_resolved_count: int = 0

    @property
    def edges(self) -> list[CallEdge]:
        return list(self._edge_map.values())

    def add_node(self, node: CallNode) -> None:
        existing = self.nodes.get(node.node_id)
        if existing is None:
            self.nodes[node.node_id] = node
            return
        # Preserve entrypoint & route annotations when merging
        merged_entry = existing.is_entrypoint or node.is_entrypoint
        merged_route = existing.route or node.route
        merged_line = existing.line if existing.line > 1 else node.line
        self.nodes[node.node_id] = existing.model_copy(
            update={
                "is_entrypoint": merged_entry,
                "route": merged_route,
                "line": merged_line,
            }
        )

    def add_edge(self, edge: CallEdge) -> None:
        key = (edge.caller, edge.callee)
        existing = self._edge_map.get(key)
        if existing is None:
            self._edge_map[key] = edge
            return
        if _PROVENANCE_RANK.get(edge.provenance, 0) > _PROVENANCE_RANK.get(existing.provenance, 0):
            self._edge_map[key] = edge

    def add_unresolved(self, site: UnresolvedCallSite) -> None:
        for existing in self.unresolved_sites:
            if (
                existing.file_path == site.file_path
                and existing.line == site.line
                and existing.expression == site.expression
            ):
                return
        self.unresolved_sites.append(site)

    def merge(self, other: CallGraph) -> None:
        """Merge another CallGraph into this one, resolving dynamic gaps when runtime edges match."""
        for node in other.nodes.values():
            self.add_node(node)

        runtime_callers: set[str] = set()
        runtime_locations: set[tuple[str, int]] = set()
        for edge in other.edges:
            self.add_edge(edge)
            if edge.provenance == "runtime_observed":
                runtime_callers.add(edge.caller)
                runtime_locations.add((edge.file_path, edge.line))

        for site in other.unresolved_sites:
            self.add_unresolved(site)

        if runtime_callers or runtime_locations:
            remaining: list[UnresolvedCallSite] = []
            for site in self.unresolved_sites:
                if (site.file_path, site.line) in runtime_locations or site.caller in runtime_callers:
                    self.runtime_resolved_count += 1
                else:
                    remaining.append(site)
            self.unresolved_sites = remaining

    def adjacency(self) -> dict[str, list[CallEdge]]:
        adj: dict[str, list[CallEdge]] = {}
        for edge in self._edge_map.values():
            adj.setdefault(edge.caller, []).append(edge)
        return adj

    def reverse_adjacency(self) -> dict[str, list[CallEdge]]:
        rev: dict[str, list[CallEdge]] = {}
        for edge in self._edge_map.values():
            rev.setdefault(edge.callee, []).append(edge)
        return rev

    def shortest_path_from_entrypoints(
        self,
        target_predicate: Callable[[str], bool],
        max_depth: int = 12,
    ) -> tuple[list[str], list[EdgeProvenance]] | None:
        """BFS from entrypoint nodes to any callee matching `target_predicate`."""
        adj = self.adjacency()
        starts = [nid for nid, n in self.nodes.items() if n.is_entrypoint]
        if not starts:
            starts = [nid for nid in self.nodes if nid.endswith("::<module>")]
        if not starts:
            starts = list(self.nodes.keys())

        visited: set[str] = set()
        queue: deque[tuple[str, list[str], list[EdgeProvenance]]] = deque()
        for s in starts:
            if target_predicate(s):
                return ([s], [])
            visited.add(s)
            queue.append((s, [s], []))

        while queue:
            curr, path, provs = queue.popleft()
            if len(path) > max_depth:
                continue
            for edge in adj.get(curr, ()):
                nxt = edge.callee
                next_path = [*path, nxt]
                next_provs = [*provs, edge.provenance]
                if target_predicate(nxt):
                    return (next_path, next_provs)
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, next_path, next_provs))
        return None

    def find_route_for_location(self, file_path: str, line: int) -> str | None:
        """Find an HTTP route whose handler calls the symbol enclosing `(file_path, line)`."""
        # Find best matching node in `file_path` at or before `line`
        candidates = [
            n
            for n in self.nodes.values()
            if n.file_path == file_path and n.line <= line and n.symbol != "<module>"
        ]
        if not candidates:
            candidates = [n for n in self.nodes.values() if n.file_path == file_path]
        if not candidates:
            return None
        target = max(candidates, key=lambda n: n.line)
        if target.route:
            return target.route

        rev = self.reverse_adjacency()
        visited = {target.node_id}
        queue: deque[str] = deque([target.node_id])
        while queue:
            curr = queue.popleft()
            node = self.nodes.get(curr)
            if node and node.route:
                return node.route
            for edge in rev.get(curr, ()):
                if edge.caller not in visited:
                    visited.add(edge.caller)
                    queue.append(edge.caller)
        return None

    def to_summary(self) -> CallGraphSummary:
        counts: dict[str, int] = {}
        for edge in self._edge_map.values():
            counts[edge.provenance] = counts.get(edge.provenance, 0) + 1
        entrypoints = sorted(
            (f"{n.node_id} ({n.route})" if n.route else n.node_id)
            for n in self.nodes.values()
            if n.is_entrypoint
        )
        return CallGraphSummary(
            total_nodes=len(self.nodes),
            total_edges=len(self._edge_map),
            edges_by_provenance=counts,
            entrypoints=entrypoints[:50],
            unresolved_sites=self.unresolved_sites[:50],
            runtime_resolved_count=self.runtime_resolved_count,
        )
