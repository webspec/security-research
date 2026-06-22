# Webspec Security Research

A public set of security research artifacts maintained by Webspec.

This repository is not meant to become a large collection of every indicator we
see. It is for artifacts connected to activity we have observed trying to
compromise sites we maintain, including cases where no compromise occurred.

Published items are selected because they appear useful to the public and meet a
high-confidence standard intended to keep false positives at a minimum.

## Layout

- [`yara/`](yara/) contains YARA rules for malware, webshell, redirect, persistence, and other IOC patterns.
- [`dga/`](dga/) contains domain lists and reference screenshots for tracked DGA or related domain clusters.
- [`hashes/`](hashes/) contains cryptographic and fuzzy hashes for tracked malware and IOC samples.

## Issues

Use GitHub issues for parser errors, false positives, unclear metadata, or
documentation fixes.

For false positives, include the rule name, scanner version, and why the matched
file is expected to be clean.

Do not attach malware, full site files, database dumps, secrets, credentials,
private keys, or live access.

Please do not submit malware samples through issues for new requests.

## License

CC BY 4.0. See [LICENSE.md](LICENSE.md).
