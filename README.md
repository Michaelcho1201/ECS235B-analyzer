# ECS235B-analyzer

## Overview

## Installation

### Development

Prerequisites: **Python 3.10+** and a working **libclang** installation (required by the `libclang` Python package).

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

This installs the package in editable mode so code changes take effect without reinstalling.

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