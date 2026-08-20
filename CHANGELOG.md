# Changelog

All notable changes to REST Lockdown are documented here.

## [1.0.0] - 2026-08-21

First public release.

### Added

- Disabled WordPress Application Passwords.
- REST write rate limiting by source IP.
- REST write rate limiting by authenticated WordPress user.
- Protection for posts, pages, media, users, comments and `/batch/v1`.
- Forensic REST request tracing.
- Unique REST trace IDs.
- Source IP and request metadata logging.
- Authenticated WordPress user identification.
- `/batch/v1` sub-request method and path tracing.
- Safe batch body-field inspection.
- Optional redacted request-body excerpts.
- REST response tracing.
- HTTP status and `WP_Error` tracking.
- Batch response status tracking.
- Successful post/page creation tracking.
- Automatic quarantine of offending posts/pages by moving them to Trash when the authenticated-user threshold is tripped.
- Automatic session invalidation after an authenticated-user threshold trip.
- Administrator email alerts.
- XML-RPC content-mutation lockdown.
- Configurable IP allowlisting.
- Optional Cloudflare client-IP handling.
- Configurable forensic logging.

### Security

- Sensitive authentication headers and credentials are not logged.
- Request-body tracing is disabled by default.
- Quarantine only applies to configured post types and verifies post ownership before moving content to Trash.
- The plugin is designed as an emergency containment and forensic-response tool while the underlying compromise is investigated and remediated.

