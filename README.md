# unwrap — PL/SQL Bulk Unwrapper

A fast, cross-platform CLI tool to unwrap Oracle PL/SQL 10g+ wrapped code.

Written in Rust — single binary, no runtime dependencies, works on **macOS**, **Linux**, and **Windows**.

## Installation

Download the latest binary for your platform from the [Releases](../../releases) page and place it in your `PATH`.

### From source

```bash
cargo install --path .
```

Or build manually:

```bash
cargo build --release
cp target/release/unwrap /usr/local/bin/
```

## Usage

```bash
# Unwrap all .pkw and .plb files in a directory (recursive)
unwrap -i ./my_wrapped_files -p '\.(pkw|plb)$'

# Unwrap a single file
unwrap -i ./package.plb -p '\.plb$'

# Unwrap to a specific output directory
unwrap -i ./my_wrapped_files -p '\.(pkw|plb|pks)$' -o ./output
```

### Options

| Option | Short | Description |
|---|---|---|
| `--input <PATH>` | `-i` | Input file or directory path (required) |
| `--pattern <REGEX>` | `-p` | Regex to match filenames (required) |
| `--output-dir <DIR>` | `-o` | Output directory (default: same as input file) |
| `--help` | `-h` | Print help |
| `--version` | `-V` | Print version |

### Output naming

`filename.ext` → `filename_unwrapped.ext`

For example:
- `my_package.pkb` → `my_package_unwrapped.pkb`
- `utils.plb` → `utils_unwrapped.plb`

## How it works

Oracle 10g+ wraps PL/SQL source code using:
1. **Base64 encoding** of the payload
2. A 20-byte header (SHA-1 hash)
3. A **256-byte substitution cipher**
4. **zlib compression**

This tool reverses the process:
1. Extracts the base64 payload from the wrapped file
2. Decodes base64
3. Skips the 20-byte Oracle header
4. Applies the reverse substitution cipher
5. Decompresses with zlib
6. Outputs clean `CREATE OR REPLACE ...` PL/SQL source

## Supported file types

Any Oracle wrapped file format, including:
- `.plb` (PL/SQL body)
- `.pkb` (package body)
- `.pks` (package spec)
- `.pkw` (wrapped package)
- `.fnc`, `.prc`, `.trg`, etc.

## License

[MIT](LICENSE)
