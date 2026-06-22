# Webspec Hash Indicators

A public set of malware and IOC sample hashes maintained by Webspec.

## Layout

Each folder contains one hash type.

- `md5/`, `sha1/`, `sha256/`, `sha3_384/`, and `blake3_256/` contain cryptographic hashes.
- `ssdeep/` and `tlsh/` contain fuzzy hashes for similarity matching.

Each folder includes:

- `all.json` with records using `category` and `hash` fields.
- `all.csv` with the same data in CSV format.

## Categories

The `category` field groups hashes by the related malware, redirect, webshell, or IOC family being tracked.

## Issues

Use GitHub issues for broken formatting, duplicate hashes, unclear categories, or documentation fixes.

Do not attach malware, full site files, database dumps, secrets, credentials, private keys, or live access.

Please do not submit malware samples through issues for new hash requests.

## License

CC BY 4.0. See [LICENSE.md](../LICENSE.md).
