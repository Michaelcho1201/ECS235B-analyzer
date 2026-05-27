"""Command-line interface: analyze one C/C++ file or all sources under a directory."""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
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


def _normalize_issue(
    issue: dict,
) -> tuple[str, str, int, int, str, str, str, str]:
    file = issue.get("file", "<unknown>")
    if hasattr(file, "name"):
        file = file.name
    line = int(issue.get("line", 0))
    column = int(issue.get("column", 0))
    severity = str(issue.get("severity", "?"))
    message = str(issue.get("message", ""))
    cwe = str(issue.get("cwe") or "")
    cvss_range = str(issue.get("cvss_range") or "")
    recommendation = str(issue.get("recommendation") or "")
    return (
        severity,
        file,
        line,
        column,
        message,
        cwe,
        cvss_range,
        recommendation,
    )


def _ansi(color: bool, code: str) -> str:
    if not color:
        return ""
    return code


def _table_usable_width() -> int:
    """Character width available for the issue table (account for leading indent)."""
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 120
    # main() prints each table line with a two-space prefix
    return max(48, min(cols - 2, 200))


def _wrap_cell(text: str, width: int, *, max_lines: int) -> list[str]:
    """Split text into lines of at most `width` chars; cap height and mark truncation."""
    text = (text or "").replace("\n", " ")
    if width <= 0:
        return [""]
    if not text:
        return ["".ljust(width)]
    raw = textwrap.wrap(
        text,
        width=width,
        break_long_words=True,
        break_on_hyphens=False,
    )
    if not raw:
        return ["".ljust(width)]
    if len(raw) <= max_lines:
        return [ln[:width].ljust(width) for ln in raw]
    head = raw[: max_lines - 1]
    tail = " ".join(raw[max_lines - 1 :])
    if len(tail) > width:
        tail = tail[: max(0, width - 1)] + "…"
    head.append(tail[:width].ljust(width))
    return [ln[:width].ljust(width) for ln in head]


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
        "CRITICAL": _ansi(color, "\033[35m"),
        "HIGH": _ansi(color, "\033[33m"),
        "WARNING": _ansi(color, "\033[33m"),
        "ERROR": _ansi(color, "\033[31m"),
        "FATAL": _ansi(color, "\033[31m"),
        "NOTE": _ansi(color, "\033[36m"),
        "UNKNOWN": _ansi(color, "\033[35m"),
    }

    usable = _table_usable_width()
    sep = " "

    w_sev = max(len("Severity"), max((len(r[0]) for r in rows), default=0))
    w_loc = max(
        len("Location"),
        max((len(f"L{r[2]}:{r[3]}") for r in rows), default=0),
    )
    w_cvss = max(len("CVSS_RANGE"), max((len(r[6]) for r in rows), default=0))
    # CWE column: cap width; long values wrap on continuation lines
    max_cwe = max((len(r[5]) for r in rows), default=0)
    w_cwe = max(len("CWE"), min(max_cwe, 22))
    fixed = w_sev + w_loc + w_cvss + w_cwe + 5 * len(sep)
    while fixed + 28 > usable and w_cwe > 6:
        w_cwe -= 1
        fixed = w_sev + w_loc + w_cvss + w_cwe + 5 * len(sep)

    rem = max(28, usable - fixed)
    min_rec = len("Recommendation")
    w_msg = max(len("Issue"), rem // 2)
    w_rec = rem - w_msg
    if w_rec < min_rec:
        w_rec = min_rec
        w_msg = max(len("Issue"), rem - w_rec)
    if w_msg < 12:
        w_msg = 12
        w_rec = max(min_rec, rem - w_msg)

    table_width = w_sev + w_loc + w_msg + w_cwe + w_cvss + w_rec + 5 * len(sep)

    lines: list[str] = []
    header = (
        f"{bold}{'Severity'.ljust(w_sev)}{sep}"
        f"{'Location'.ljust(w_loc)}{sep}"
        f"{'Issue'.ljust(w_msg)}{sep}"
        f"{'CWE'.ljust(w_cwe)}{sep}"
        f"{'CVSS_RANGE'.ljust(w_cvss)}{sep}"
        f"{'Recommendation'.ljust(w_rec)}{reset}"
    )
    underline = f"{dim}{'─' * table_width}{reset}"
    lines.append(header)
    lines.append(underline)

    pad_sev = " " * w_sev
    pad_loc = " " * w_loc

    for sev, _file, line, col, msg, cwe, cvss, rec in rows:
        style = sev_styles.get(sev, "")
        loc = f"L{line}:{col}"
        sev_plain = sev.ljust(w_sev)
        sev_colored = f"{style}{sev_plain}{reset}"

        msg_lines = _wrap_cell(msg, w_msg, max_lines=6)
        cwe_lines = _wrap_cell(cwe, w_cwe, max_lines=3)
        cvss_lines = _wrap_cell(cvss, w_cvss, max_lines=1)
        rec_lines = _wrap_cell(rec, w_rec, max_lines=5)

        n = max(len(msg_lines), len(cwe_lines), len(cvss_lines), len(rec_lines))
        msg_lines.extend(["".ljust(w_msg)] * (n - len(msg_lines)))
        cwe_lines.extend(["".ljust(w_cwe)] * (n - len(cwe_lines)))
        cvss_lines.extend(["".ljust(w_cvss)] * (n - len(cvss_lines)))
        rec_lines.extend(["".ljust(w_rec)] * (n - len(rec_lines)))

        for i in range(n):
            sev_cell = sev_colored if i == 0 else pad_sev
            loc_cell = loc.ljust(w_loc) if i == 0 else pad_loc
            lines.append(
                f"{sev_cell}{sep}{loc_cell}{sep}{msg_lines[i]}{sep}"
                f"{cwe_lines[i]}{sep}{cvss_lines[i]}{sep}{rec_lines[i]}"
            )
        lines.append("")

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
