# Samsung Pass Converter

This script decrypts Samsung Pass `.spass` export files and converts them into a Bitwarden compatible CSV format for easy import.

## Features

- Decrypts `.spass` files exported from Samsung Pass, using the password provided during export.
- Exports credentials to a Bitwarden-compatible CSV file.
- Optionally saves all processed decrypted data (`--all`).

## Requirements

- Python 3.6+
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:

```sh
pip install cryptography
```

## Usage

<export_file_path>: Path to your .spass file.
<password>: Password used for Samsung Pass export.
--all: (Optional) Save all processed decrypted data to a .decrypted.txt file.

### Example:

```py
python convert.py <export_file_path> <password> [--all]
```

- \<export_file_path>: Path to your .spass file.
- \<password>: Password used while exporting Samsung Pass content.
- --all: (Optional) Save all processed decrypted data to a .decrypted.txt file.

### This will produce:

- myexport.bitwarden.csv (Bitwarden importable CSV)
- myexport.decrypted.txt (if --all is used)

## Legal Notice

This script is intended for personal use to migrate your own data from Samsung Pass to Bitwarden.
Do not use this tool on files you do not own or have permission to access.

## Disclaimer

This project is not affiliated with, endorsed by, or supported by Samsung or Bitwarden.
Use at your own risk.
