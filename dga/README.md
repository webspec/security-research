# Webspec DGA Domains

A public set of domain generation algorithm domains maintained by Webspec.

## Layout

Each folder contains domains for one tracked DGA or related domain cluster.

### Domains

Domain lists use one domain per line:

- `alive.txt` contains domains that were live when last checked.
- `dead.txt` contains domains that were known but inactive when last checked.

### Screenshots

Some folders include `screenshots/` with deduplicated reference screenshots for live domains.

The screenshot builder groups visually similar pages into `reference-*.png` images. It also creates `screenshot_references.json`, which maps each reference image to the domains and screenshot times used to build it.

`screenshot_references.json` is generated metadata and is not included in this repository.

## Issues

Use GitHub issues for missing context, broken formatting, or documentation fixes.

Do not attach malware, full site files, secrets, credentials, private keys, or live access.

Please do not submit malware samples through issues for new cluster requests.

## License

CC BY 4.0. See [LICENSE.md](../LICENSE.md).
