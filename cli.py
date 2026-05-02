"""Command-line interface: analyze one C/C++ file or all sources under a directory."""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from pathlib import Path

from analyzer import Analyzer

# Extensions Clang commonly treats as C/C++ translation units
CPP_SUFFIXES = frozenset({
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".inl",
    ".ipp",
})


def _suffix_key(path: Path) -> str:
    return path.suffix.lower()


def collect_cpp_paths(root: Path) -> list[Path]:
    """Return sorted list of C/C++ file paths for a file or directory."""
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    if root.is_file():
        if _suffix_key(root) not in CPP_SUFFIXES:
            print(
                f"Error: not a C/C++ source file (expected suffix in {sorted(CPP_SUFFIXES)}): {root}",
                file=sys.stderr,
            )
            sys.exit(1)
        return [root.resolve()]

    paths: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and _suffix_key(p) in CPP_SUFFIXES:
            paths.append(p.resolve())
    return sorted(paths)


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _normalize_issue(issue: dict) -> tuple[str, str, int, int, str]:
    file = issue.get("file", "<unknown>")
    if hasattr(file, "name"):
        file = file.name
    line = int(issue.get("line", 0))
    column = int(issue.get("column", 0))
    severity = str(issue.get("severity", "?"))
    message = str(issue.get("message", ""))
    return severity, file, line, column, message


def _ansi(color: bool, code: str) -> str:
    if not color:
        return ""
    return code


def _format_issues_block(
    issues: list[dict],
    *,
    color: bool,
) -> str:
    rows = [_normalize_issue(i) for i in issues]
    rows.sort(key=lambda r: (r[1], r[2], r[3]))

    reset = _ansi(color, "\033[0m")
    bold = _ansi(color, "\033[1m")
    dim = _ansi(color, "\033[2m")

    sev_styles = {
        "WARNING": _ansi(color, "\033[33m"),
        "ERROR": _ansi(color, "\033[31m"),
        "FATAL": _ansi(color, "\033[31m"),
        "NOTE": _ansi(color, "\033[36m"),
        "UNKNOWN": _ansi(color, "\033[35m"),
    }

    w_sev = max(len("Severity"), max((len(r[0]) for r in rows), default=0))
    w_loc = max((len(f"L{r[2]}:{r[3]}") for r in rows), default=len("Location"))

    lines: list[str] = []
    header = f"{bold}{'Severity'.ljust(w_sev)}  {'Location'.ljust(w_loc)}  Issue{reset}"
    underline = f"{dim}{'─' * (w_sev + 2 + w_loc + 2 + 20)}{reset}"
    lines.append(header)
    lines.append(underline)

    for sev, _file, line, col, msg in rows:
        style = sev_styles.get(sev, "")
        loc = f"L{line}:{col}"
        sev_colored = f"{style}{sev.ljust(w_sev)}{reset}"
        lines.append(f"{sev_colored}  {loc.ljust(w_loc)}  {msg}")

    return "\n".join(lines)


def _rule_separator(*, color: bool) -> str:
    dim = _ansi(color, "\033[2m")
    reset = _ansi(color, "\033[0m")
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80
    width = min(72, max(48, cols - 2))
    return f"{dim}{'─' * width}{reset}"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="Parse C/C++ files with libclang and run vulnerability checks.",
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to a C/C++ file or a directory (searched recursively)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors even when output is a terminal",
    )
    args = parser.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()
    paths = collect_cpp_paths(args.path.resolve())
    if not paths:
        print("No C/C++ files found in that directory.", file=sys.stderr)
        sys.exit(1)

    analyzer = Analyzer()
    exit_code = 0
    total_counts: Counter[str] = Counter()

    print(_rule_separator(color=use_color))
    print(f"Analyzing {len(paths)} file(s)\n")

    for fp in paths:
        label = _display_path(fp)
        issues = analyzer.analyze(str(fp))
        total_counts.update(_normalize_issue(i)[0] for i in issues)

        print(_rule_separator(color=use_color))
        print(f"File: {label}")
        print(f"Path: {fp}\n")

        if not issues:
            print("  No issues reported.\n")
            continue

        exit_code = 1
        block = _format_issues_block(issues, color=use_color)
        for line in block.splitlines():
            print(f"  {line}")
        print()

    print(_rule_separator(color=use_color))
    print("Summary")
    print(f"  Files analyzed: {len(paths)}")
    print(f"  Total issues:   {sum(total_counts.values())}")
    if total_counts:
        parts = [f"{sev}: {n}" for sev, n in sorted(total_counts.items())]
        print(f"  By severity:    {', '.join(parts)}")
    else:
        print("  By severity:    (none)")
    print(_rule_separator(color=use_color))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
