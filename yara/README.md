# Webspec YARA Rules

A public set of YARA rules maintained by Webspec. Rules mostly cover malware and IOC patterns for WordPress/PHP/JS.

Rules are written for YARA-X and kept compatible with older YARA releases where practical.

## Yaraw

### Metadata

Yaraw is Webspec tooling built around YARA scanning. Some rules include extra metadata for Yaraw:

- `db_scan = true` tells Yaraw the rule is meant for normalized database dump scans.
- `actions` tells Yaraw what remediation step is approved for that detection. This supports automated remediation at Webspec scale.

These fields are not part of the YARA language. Other scanners can ignore them.

### WordPress Database Dumps

For those without access to Yaraw, database rules can still be used against a WordPress database dump.
From the WordPress root, export the database with:

```sh
wp db export /tmp/dump.sql --quiet
```

Then scan the dump with YARA:

```sh
yara rules/*.yar /tmp/dump.sql
```

## Issues

Use GitHub issues for parser errors, false positives, unclear metadata, or documentation fixes.

For false positives, include the rule name, YARA version, and why the matched file is expected to be clean.
Do not attach malware, full site files, database dumps, secrets, credentials, private keys, or live access.

Please do not submit malware samples through issues for new rule requests.

## License

CC BY 4.0. See [LICENSE.md](../LICENSE.md).
