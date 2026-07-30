"""Static call graph construction for a Python project.

The graph answers one question: starting from the application's entrypoints,
which third-party symbols can execution actually reach?

Approach (intraprocedural, import-aware):
  1. Parse every .py file in the project with `ast`.
  2. Record each module's import table, mapping local aliases to fully
     qualified names (`import numpy as np` -> np == numpy).
  3. Walk each function body, resolving every Call node against that table to
     produce an outgoing edge.
  4. Identify entrypoints: `__main__` blocks, CLI commands, web route handlers,
     and any public module-level function not called by anything else.

Known limits (documented rather than hidden -- see docs/05_results_and_discussion.md):
dynamic dispatch via getattr/eval, callables passed as arguments, and
monkey-patching are not resolved. Those cases are reported as
POTENTIALLY_REACHABLE rather than silently dropped.
"""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path

# Decorators that mark a function as externally invoked (a web request, a CLI
# command, a scheduled job). Anything they wrap is an entrypoint by definition.
_ENTRYPOINT_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch",  # Flask / FastAPI
    "command", "group",                                 # Click / Typer
    "task", "job", "scheduled",                         # Celery / schedulers
    "app", "callback", "on_event", "websocket",
}

# Calls that defeat static resolution. Their presence in a function widens that
# function's verdict from UNREACHABLE to POTENTIALLY_REACHABLE.
_DYNAMIC_CALLS = {"getattr", "eval", "exec", "__import__", "importlib", "globals", "vars"}


@dataclass
class FunctionNode:
    """One function or method in the project's own source."""

    qualname: str
    module: str
    name: str
    lineno: int
    calls: set[str] = field(default_factory=set)
    is_entrypoint: bool = False
    uses_dynamic_dispatch: bool = False


@dataclass
class CallGraph:
    """Project call graph plus the import tables used to build it."""

    nodes: dict[str, FunctionNode] = field(default_factory=dict)
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    module_imports: dict[str, dict[str, str]] = field(default_factory=dict)
    external_calls: set[str] = field(default_factory=set)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def entrypoints(self) -> list[str]:
        return sorted(q for q, n in self.nodes.items() if n.is_entrypoint)

    def successors(self, qualname: str) -> set[str]:
        return self.edges.get(qualname, set())


class _ModuleVisitor(ast.NodeVisitor):
    """Collects imports, function definitions and call edges for one module."""

    def __init__(self, module: str, graph: CallGraph):
        self.module = module
        self.graph = graph
        self.imports: dict[str, str] = {}
        self._scope: list[str] = []
        self._current: FunctionNode | None = None
        graph.module_imports[module] = self.imports

    # -- imports ---------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.imports[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Relative imports refer to the project itself, not a dependency.
        if node.level and node.level > 0:
            base = self.module.rsplit(".", node.level)[0] if "." in self.module else ""
            prefix = f"{base}.{node.module}" if node.module and base else (node.module or base)
        else:
            prefix = node.module or ""

        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = f"{prefix}.{alias.name}" if prefix else alias.name
        self.generic_visit(node)

    # -- definitions -----------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function(node)

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([self.module, *self._scope, node.name])
        fn = FunctionNode(
            qualname=qualname,
            module=self.module,
            name=node.name,
            lineno=node.lineno,
            is_entrypoint=self._is_entrypoint(node),
        )
        self.graph.nodes[qualname] = fn

        previous, self._current = self._current, fn
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()
        self._current = previous

    def _is_entrypoint(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if node.name == "main":
            return True
        for dec in node.decorator_list:
            for name in self._decorator_names(dec):
                if name in _ENTRYPOINT_DECORATORS:
                    return True
        return False

    @staticmethod
    def _decorator_names(dec: ast.expr) -> list[str]:
        """Every identifier in a decorator, so @app.route and @app.get both hit."""
        names: list[str] = []
        for sub in ast.walk(dec):
            if isinstance(sub, ast.Name):
                names.append(sub.id)
            elif isinstance(sub, ast.Attribute):
                names.append(sub.attr)
        return names

    # -- calls -----------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        target = self._resolve_call(node.func)
        if target:
            if target.split(".", 1)[0] in _DYNAMIC_CALLS or target in _DYNAMIC_CALLS:
                if self._current:
                    self._current.uses_dynamic_dispatch = True
            elif self._current:
                self._current.calls.add(target)
                self.graph.edges[self._current.qualname].add(target)
            else:
                # Module-level call: attribute it to a synthetic module node so
                # import-time side effects are not lost.
                module_node = self._module_level_node()
                module_node.calls.add(target)
                self.graph.edges[module_node.qualname].add(target)
        self.generic_visit(node)

    def _module_level_node(self) -> FunctionNode:
        qualname = f"{self.module}:<module>"
        node = self.graph.nodes.get(qualname)
        if node is None:
            node = FunctionNode(
                qualname=qualname,
                module=self.module,
                name="<module>",
                lineno=0,
                is_entrypoint=True,  # import-time code always executes
            )
            self.graph.nodes[qualname] = node
        return node

    def _resolve_call(self, func: ast.expr) -> str | None:
        """Turn a call target AST into a fully qualified dotted name."""
        dotted = self._dotted_name(func)
        if not dotted:
            return None

        head, _, tail = dotted.partition(".")
        origin = self.imports.get(head)
        if origin is None:
            # Not an imported name: a local function, a builtin, or a method on
            # an object we cannot type-infer. Keep it unqualified.
            return dotted

        resolved = f"{origin}.{tail}" if tail else origin
        self.graph.external_calls.add(resolved)
        return resolved

    @staticmethod
    def _dotted_name(node: ast.expr) -> str | None:
        parts: list[str] = []
        current: ast.expr | None = node
        while True:
            if isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            elif isinstance(current, ast.Name):
                parts.append(current.id)
                break
            elif isinstance(current, ast.Call):
                # Chained call: foo().bar() -- descend to the base receiver.
                current = current.func
            else:
                return None
        return ".".join(reversed(parts))


def build_call_graph(
    project_path: str | Path,
    *,
    exclude: tuple[str, ...] = ("test", "tests", ".venv", "venv", "build", "dist",
                                "__pycache__", "site-packages", "node_modules"),
) -> CallGraph:
    """Parse a project tree and return its call graph."""
    root = Path(project_path).expanduser().resolve()
    graph = CallGraph()

    for py_file in sorted(root.rglob("*.py")):
        rel = py_file.relative_to(root)
        if any(part in exclude for part in rel.parts):
            continue

        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, ValueError, OSError) as exc:
            graph.parse_errors.append(f"{rel}: {exc}")
            continue

        module = ".".join(rel.with_suffix("").parts)
        _ModuleVisitor(module, graph).visit(tree)

    _mark_orphan_entrypoints(graph)
    return graph


def _mark_orphan_entrypoints(graph: CallGraph) -> None:
    """Treat uncalled public functions as entrypoints.

    A public function nothing else calls is either dead code or an externally
    invoked API. Assuming the latter is the safe direction: it can only widen
    reachability, never hide a real path.
    """
    called: set[str] = set()
    for targets in graph.edges.values():
        called.update(targets)

    # Edges store resolved names; project functions may be called by bare name.
    bare_called = {t.rsplit(".", 1)[-1] for t in called}

    for qualname, node in graph.nodes.items():
        if node.is_entrypoint or node.name.startswith("_"):
            continue
        if qualname not in called and node.name not in bare_called:
            node.is_entrypoint = True


def reachable_external_symbols(
    graph: CallGraph, max_hops: int = 12
) -> dict[str, list[tuple[str, tuple[str, ...]]]]:
    """BFS from every entrypoint, collecting external symbols and their paths.

    Returns {external_symbol: [(entrypoint, intermediate_steps), ...]}.
    """
    project_modules = {n.module for n in graph.nodes.values()}
    results: dict[str, list[tuple[str, tuple[str, ...]]]] = defaultdict(list)

    # Index project functions by bare name so unqualified internal calls resolve.
    by_bare_name: dict[str, list[str]] = defaultdict(list)
    for qualname, node in graph.nodes.items():
        by_bare_name[node.name].append(qualname)

    def is_internal(target: str) -> list[str]:
        """Project-local functions a call target could refer to."""
        if target in graph.nodes:
            return [target]
        head = target.split(".", 1)[0]
        if head in project_modules or target.rsplit(".", 1)[0] in project_modules:
            return [q for q in by_bare_name.get(target.rsplit(".", 1)[-1], [])]
        return by_bare_name.get(target, []) if "." not in target else []

    for entry in graph.entrypoints:
        queue: deque[tuple[str, tuple[str, ...]]] = deque([(entry, ())])
        seen: set[str] = {entry}

        while queue:
            current, path = queue.popleft()
            if len(path) >= max_hops:
                continue

            for target in graph.successors(current):
                internal = is_internal(target)
                if internal:
                    for node_name in internal:
                        if node_name not in seen:
                            seen.add(node_name)
                            queue.append((node_name, (*path, node_name)))
                else:
                    results[target].append((entry, path))

    return dict(results)
