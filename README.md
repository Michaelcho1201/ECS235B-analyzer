# ECS235B — Static Code Analyzer

A static analyzer for C++ that inspects source code **without running it** and reports
likely bugs and vulnerabilities — deprecated APIs, buffer overflows, memory leaks, null
dereferences, and more — pointing you to the exact line where each issue occurs.

You can run the full suite for a thorough analysis, or target a single check. See
[Features](#features) for what it detects and [Usage](#usage) for how to run it.


---

## Features

| Check | What it detects |
| --- | --- |
| **Deprecated Functions** | Use of dangerous or deprecated functions listed in the database. |
| **Syntax Errors** | Syntax issues surfaced through libclang diagnostics. |
| **Null Dereference** | Code paths that may dereference a null pointer. |
| **Buffer Overflow** | Fixed-size arrays, loop indexing, unsafe string/memory copies, and unbounded input. |
| **Memory Leak** | Heap allocations that are never freed (tagged with CWE/CVSS metadata). |
| **Symbolic Execution** | Path exploration for division by zero, null deref, and out-of-bounds access. |
| **Tainted Data** | Untrusted input flowing into sensitive operations. |
| **Uninitialized Variables** | Variables read before being assigned a value. |
| **Unused Variables** | Variables that are declared but never used. |

---

## Installation

### Prerequisites

**Windows 11**
- **LLVM** — download and install [LLVM-22.1.0-win64.exe](https://github.com/llvm/llvm-project/releases/tag/llvmorg-22.1.0)
- **libclang** — `pip install libclang`
- **clang** — `pip install clang`

**Linux**
- **Python 3.10+**
- **GCC** — used by libclang to locate system headers (`sudo apt install gcc`)
- **Clang / libclang 16+** — `sudo apt install clang`

### Setup

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

This installs the package in editable mode, so code changes take effect without reinstalling.

### Header search path

libclang needs Clang's built-in headers (`stddef.h`, `stdarg.h`, etc.). If you see errors like
`'stddef.h' file not found` during analysis, set `CPATH` before running:

```bash
export CPATH=$(clang -print-resource-dir)/include
```

To set it automatically on every `source .venv/bin/activate`, append it to the activate script:

```bash
echo 'export CPATH=$(clang -print-resource-dir)/include' >> .venv/bin/activate
```

---

## Usage

After a development install, the CLI entry point is **`analyze`**:

```bash
analyze path/to/file.cpp
analyze path/to/project_dir
```

Without installing the package, run the CLI module directly from the repo root:

```bash
python cli.py path/to/file_or_directory
```

**Options**

| Flag | Description |
| --- | --- |
| `--no-color` | Disable ANSI colors in the output. |

---

## Project Structure

```
ECS235B-analyzer/
├── cli.py                 # Command-line interface
├── pyproject.toml         # Project configuration
├── src/
│   ├── parser/            # Parser modules
│   └── rules/             # Analysis rules
└── tests/                 # Test suite
```