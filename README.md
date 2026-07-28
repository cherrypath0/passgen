# passgen

A secure, cross-platform command-line password generator written in C. Works natively on Linux, macOS, and Windows without external dependencies.

## Features

- **Secure randomness**: Uses `/dev/urandom` on Linux/macOS and `CryptGenRandom` on Windows
- **Unbiased selection**: Rejection sampling eliminates modulo bias
- **Customizable length**: Set password length (default: 16 characters)
- **Batch generation**: Generate multiple passwords at once (up to 100)
- **Character set control**: Include/exclude letters, numbers, uppercase, lowercase, or symbols
- **Custom charset**: Define your own character set
- **Security warnings**: Warns when settings may produce weak passwords
- **Single file**: Entire tool is one self-contained C file

## Installation

### From Source

#### Linux
```bash
gcc -O2 -o passgen passgen.c
```

#### macOS
```bash
clang -O2 -o passgen passgen.c
```

#### Windows (MinGW)
```bash
gcc -O2 -o passgen.exe passgen.c -ladvapi32
```

#### Windows (MSVC)
```cmd
cl /O2 passgen.c advapi32.lib
```

### Move to PATH (Optional)

**Linux / macOS:**
```bash
sudo mv passgen /usr/local/bin/
```

**Windows:**
Move `passgen.exe` to a folder in your PATH, such as `C:\Windows\System32\` or `C:\Tools\`.

## Usage

```
passgen [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `-?`, `--help` | Show help message and exit |
| `-v`, `--version` | Show version information |
| `-a <N>`, `--amount <N>` | Number of passwords to generate (1-100, default: 1) |
| `-c <N>`, `--count <N>` | Characters per password (default: 16) |
| `--no-letters` | Exclude all letters (A-Z, a-z) |
| `--no-numbers` | Exclude numbers (0-9) |
| `--no-uppercase` | Exclude uppercase letters (A-Z) |
| `--no-lowercase` | Exclude lowercase letters (a-z) |
| `--no-symbols` | Exclude symbols |
| `-s <STRING>`, `--set <STRING>` | Use a custom character set |

### Examples

Generate a single 16-character password (default):
```bash
passgen
```

Generate 10 passwords, each 20 characters long:
```bash
passgen -a 10 -c 20
```

Generate a password with only numbers and symbols:
```bash
passgen --no-letters
```

Generate a password using only hex characters:
```bash
passgen -s "0123456789abcdef" -c 32
```

Generate a password with no symbols, 12 characters:
```bash
passgen --no-symbols -c 12
```

### Security Warnings

The tool will prompt for confirmation when:
- Password length is below 8 characters
- More than 2 exclusion flags are used together
- A custom character set has fewer than 16 unique characters

## How It Works

- **Entropy source**: Platform-native cryptographically secure random number generators
- **Unbiased sampling**: The tool uses rejection sampling to ensure every character in the selected set has an exactly equal probability of being chosen — no modulo bias
- **No memory allocation during generation**: Passwords are generated and printed character-by-character for simplicity and safety

## Platform Notes

| Platform | Random Source | Notes |
|----------|--------------|-------|
| Linux | `/dev/urandom` | Non-blocking, suitable for passwords |
| macOS | `/dev/urandom` | Same interface as Linux |
| Windows | `CryptGenRandom` | Windows CryptoAPI |

## License

This project is licensed under the MIT License, see the full license text by [clicking here](./LICENSE).