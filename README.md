# ECS235B - Static Code Analyzer

## Overview
This program is a static code analyzer that will analyzer a program with out having to run the program. It would check to see if it is using any deprecated functions as one of its functions, and as well syntax errors. There are other functions to the program such as buffer overflow, dangerous fucntions, memory leak, null dereferences, and symbolic executions. Together they will inspect code that may have deprecapted functions, a memory that has not been freed, or check for edge cases. The program in its entirety will check for specific issues in the code(read section features for more details) and notify the client that such issue exist at this line of the analyzed code. We have commands that would allow you to run all functions for a thorough analysis or are just the mentioned function. To learn how to do this read the development section where we show you the commands to do this. Overall this program will analyze code for certain patterns and notify the client what it has analyzed.

Authors:
- Alfredo Ortiz
- Pichsorita yim
- Tejas Khode
- Michael Cho
- Vishal Krishna Chintakunta

## Installation

### Development

Prerequisites:

 **Windows 11**
 - **LLVM**: Download LLVM-22.1.0-win64.exe from this website https://github.com/llvm/llvm-project/releases/tag/llvmorg-22.1.0 and install
 - **libclang**: install libclang using this command: pip install libclang
 - **clang**:  install clang using this command: pip install clang

**Linux**
- **Python 3.10+**
- **GCC** (used by libclang to locate system headers — install via `sudo apt install gcc` on Debian/Ubuntu)
- **Clang / libclang 16+** (`sudo apt install clang` on Debian/Ubuntu)

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

This installs the package in editable mode so code changes take effect without reinstalling.

#### Header search path

libclang needs access to Clang's built-in headers (`stddef.h`, `stdarg.h`, etc.). If you see errors like `'stddef.h' file not found` during analysis, set `CPATH` before running the analyzer:

```bash
export CPATH=$(clang -print-resource-dir)/include
```

To avoid running this every time, append it to your virtual environment's activate script so it is set automatically on `source .venv/bin/activate`:

```bash
echo 'export CPATH=$(clang -print-resource-dir)/include' >> .venv/bin/activate
```

## Usage

After a development install, the CLI entry point is **`analyze`** (defined in `pyproject.toml`):

```bash
analyze path/to/file.cpp
analyze path/to/project_dir
```

Optional flag: `--no-color` to disable ANSI colors.

Without installing the package, you can run the CLI module from the repo root:

```bash
python cli.py path/to/file_or_directory
```

## Project Structure

```
ECS235B-analyzer/
├── cli.py                 # Command-line interface
├── pyproject.toml         # Project configuration
├── src/
│   ├── parser/            # Parser modules
│   └── rules/             # Rules modules
└── tests/                 # Test suite
```

## Features

 • Deprecated Function Analysis: Detects dangerous or deprecated functions listed in the database and reports when they are used in the analyzed program.

 • Syntax Error Analysis: Uses libclang diagnostics to identify syntax errors in the analyzed source code.

 • Null Dereference Analysis: Checks for cases where the code may dereference a null pointer.

 • Buffer Overflow Analysis: Detects possible buffer overflow patterns involving fixed-size arrays, loop-based indexing, unsafe string copy functions, memory copy functions, and unbounded input.


## Contributing

## License
