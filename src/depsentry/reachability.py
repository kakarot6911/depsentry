"""Decide whether each advisory's vulnerable symbol is actually reachable.

This is the module the whole project turns on. A conventional scanner reports a
finding when a vulnerable *package version* is installed. DepSentry additionally
asks whether the *vulnerable function inside it* can be reached from application
code, and downgrades everything that cannot.

Verdict rules, in order:
  1. Package never imported anywhere in the project        -> UNREACHABLE
  2. Advisory names no symbols (nothing to trace)          -> UNKNOWN
  3. A vulnerable symbol sits on a path from an entrypoint -> REACHABLE
  4. Package imported, symbol not called, but the importing
     code uses dynamic dispatch                            -> POTENTIALLY_REACHABLE
  5. Package imported, symbol demonstrably not called      -> UNREACHABLE

Rule 4 is the safety valve. getattr/eval defeat static analysis, so rather than
claiming an unreachable verdict we cannot support, DepSentry keeps the finding
alive at reduced weight.
"""

from __future__ import annotations

from dataclasses import dataclass

from .callgraph import CallGraph, path_detail, reachable_external_symbols
from .models import CallPath, Reachability, Vulnerability


@dataclass
class ReachabilityVerdict:
    status: Reachability
    call_paths: list[CallPath]
    reason: str


def _top_level(symbol: str) -> str:
    """Distribution-ish root of a dotted symbol: 'PIL.Image.open' -> 'pil'."""
    return symbol.split(".", 1)[0].lower().replace("_", "-")


# PyPI distribution names that differ from their import name.
_IMPORT_ALIASES = {
    "pyyaml": {"yaml"},
    "pillow": {"pil"},
    "scikit-learn": {"sklearn"},
    "beautifulsoup4": {"bs4"},
    "python-dateutil": {"dateutil"},
    "typing-extensions": {"typing-extensions", "typing_extensions"},
    "attrs": {"attr", "attrs"},
    "protobuf": {"google"},
    "opencv-python": {"cv2"},
    "msgpack-python": {"msgpack"},
}


def import_names_for(package_name: str) -> set[str]:
    """Every module root a distribution might be imported as."""
    normalised = package_name.lower().replace("_", "-")
    names = {normalised, normalised.replace("-", "_"), normalised.replace("-", "")}
    names |= _IMPORT_ALIASES.get(normalised, set())
    return names


class ReachabilityAnalyzer:
    """Answers reachability questions for one project's call graph."""

    def __init__(self, graph: CallGraph, max_hops: int = 12):
        self.graph = graph
        self.reachable = reachable_external_symbols(graph, max_hops=max_hops)

        # Roots of every external symbol reachable from an entrypoint.
        self._reachable_roots = {_top_level(s) for s in self.reachable}

        # Roots of everything imported anywhere, reachable or not.
        self._imported_roots: set[str] = set()
        for table in graph.module_imports.values():
            for origin in table.values():
                self._imported_roots.add(_top_level(origin))

        # Modules whose code defeats static resolution.
        self._dynamic_modules = {
            n.module for n in graph.nodes.values() if n.uses_dynamic_dispatch
        }

    def _package_imported(self, package_name: str) -> bool:
        return bool(import_names_for(package_name) & self._imported_roots)

    def _package_dynamic(self, package_name: str) -> bool:
        """True if any module importing this package also uses dynamic dispatch."""
        aliases = import_names_for(package_name)
        for module, table in self.graph.module_imports.items():
            roots = {_top_level(origin) for origin in table.values()}
            if roots & aliases and module in self._dynamic_modules:
                return True
        return False

    def _matching_symbols(self, symbol: str) -> list[str]:
        """Reachable symbols that correspond to an advisory symbol.

        Matching is exact or suffix-anchored on a dotted boundary. This is what
        keeps `yaml.safe_load` from matching an advisory on `yaml.load`.
        """
        matches: list[str] = []
        target_tail = symbol.rsplit(".", 1)[-1]
        target_root = _top_level(symbol)

        for reached in self.reachable:
            if reached == symbol:
                matches.append(reached)
                continue
            # Same package root AND same final attribute -> same function
            # reached through a different import alias.
            if _top_level(reached) == target_root and reached.rsplit(".", 1)[-1] == target_tail:
                matches.append(reached)
                continue
            # Advisory names a class; project calls a method on it.
            if reached.startswith(symbol + "."):
                matches.append(reached)
        return matches

    def analyze(self, vuln: Vulnerability) -> ReachabilityVerdict:
        package = vuln.package

        if not self._package_imported(package):
            return ReachabilityVerdict(
                Reachability.UNREACHABLE,
                [],
                f"'{package}' is not imported anywhere in the project source.",
            )

        if not vuln.affected_symbols:
            return ReachabilityVerdict(
                Reachability.UNKNOWN,
                [],
                f"Advisory {vuln.vuln_id} names no affected symbol; "
                "cannot trace a path. Treated as unknown, not safe.",
            )

        call_paths: list[CallPath] = []
        for symbol in vuln.affected_symbols:
            for reached in self._matching_symbols(symbol):
                for entrypoint, steps in self.reachable.get(reached, []):
                    call_paths.append(
                        CallPath(
                            entrypoint=entrypoint,
                            steps=steps,
                            target_symbol=reached,
                            confidence=1.0 if reached == symbol else 0.8,
                            detail=path_detail(self.graph, entrypoint, steps, reached),
                        )
                    )

        if call_paths:
            # Shortest paths first: they are the clearest evidence for a reviewer.
            call_paths.sort(key=lambda p: len(p.steps))
            symbols = sorted({p.target_symbol for p in call_paths})
            return ReachabilityVerdict(
                Reachability.REACHABLE,
                call_paths[:5],
                f"Vulnerable symbol(s) {', '.join(symbols)} reachable from "
                f"{len({p.entrypoint for p in call_paths})} entrypoint(s).",
            )

        if self._package_dynamic(package):
            return ReachabilityVerdict(
                Reachability.POTENTIALLY_REACHABLE,
                [],
                f"'{package}' is imported and the importing module uses dynamic "
                "dispatch (getattr/eval), so static analysis cannot rule out a call.",
            )

        return ReachabilityVerdict(
            Reachability.UNREACHABLE,
            [],
            f"'{package}' is imported, but no call path reaches "
            f"{', '.join(vuln.affected_symbols)}.",
        )

    def summary(self) -> dict[str, int]:
        return {
            "entrypoints": len(self.graph.entrypoints),
            "project_functions": len(self.graph.nodes),
            "external_symbols_reached": len(self.reachable),
            "modules_with_dynamic_dispatch": len(self._dynamic_modules),
            "parse_errors": len(self.graph.parse_errors),
        }
