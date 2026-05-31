# ECS235B-analyzer

## Overview

## Installation

### Development

Prerequisites:

 **Windows 11**
 - **LLVM** Download LLVM-22.1.0-win64.exe from this website https://github.com/llvm/llvm-project/releases/tag/llvmorg-22.1.0 and install
 - **libclang** install libclang using this command: pip install libclang
 - **clang**  install clang using this command: pip install clang

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

## Contributing

## License
