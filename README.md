# REST Lockdown

**WordPress MU-plugin for REST API lockdown, forensic tracing, and automated spam containment.**

**GitHub:** https://github.com/menj/rest-lockdown

## Version

**1.0.0** — first public release.

## Important: MU-Plugin Only

REST Lockdown is designed to be installed as a **WordPress must-use plugin (`mu-plugin`)**.

It is **not** a normal plugin that should be installed through **Plugins → Add New Plugin**.

Must-use plugins are loaded automatically by WordPress and do not have an Activate/Deactivate button in the normal Plugins screen.

## Installation

### 1. Locate the MU-plugins directory

The standard directory is:

```text
wp-content/mu-plugins/
```

If the directory does not exist, create it.

### 2. Upload the plugin

Upload the file:

```text
rest-lockdown.php
```

to:

```text
wp-content/mu-plugins/rest-lockdown.php
```

The final path should be:

```text
wp-content/
└── mu-plugins/
    └── rest-lockdown.php
```

Do **not** put it in `wp-content/plugins/`.

### 3. No activation is required

WordPress automatically loads PHP files placed directly inside `wp-content/mu-plugins/`.

You can confirm it is loaded from **WordPress → Plugins → Must-Use**.

## Configuration

Configuration constants are near the top of `rest-lockdown.php`.

Important settings include:

```php
define( 'BRL_ALLOWED_IPS', array() );
define( 'BRL_BEHIND_CLOUDFLARE', false );
define( 'BRL_RATE_LIMIT_MAX', 5 );
define( 'BRL_RATE_LIMIT_WINDOW', 600 );
define( 'BRL_AUTO_KILL_SESSION', true );
define( 'BRL_ALERT_EMAIL', 'contact@menj.org' );
define( 'BRL_DELETE_OFFENDING_CONTENT', true );
define( 'BRL_DELETE_POST_TYPES', array( 'post', 'page' ) );
define( 'BRL_TRACE_REST', true );
define( 'BRL_TRACE_RESPONSES', true );
define( 'BRL_TRACE_BODY', false );
```

For an active incident, keep forensic tracing enabled and leave request-body tracing disabled unless body-level evidence is specifically required.

## What it protects

The MU-plugin monitors and protects REST write activity involving:

- `/wp/v2/posts`
- `/wp/v2/pages`
- `/wp/v2/media`
- `/wp/v2/users`
- `/wp/v2/comments`
- `/batch/v1`

It also disables WordPress Application Passwords and restricts content-mutating XML-RPC methods.

## REST forensic tracing

The trace records relevant information about REST requests, including source IP as observed by PHP, HTTP method, REST route, request URI, User-Agent, Referer, authenticated WordPress user, authentication state, request size, content type, CLI/Cron execution context, and a unique trace ID.

### `/batch/v1`

Batch requests are inspected for:

- valid/invalid batch JSON
- number of sub-requests
- sub-request methods
- sub-request paths
- submitted body field names

Sensitive credentials are not logged by default.

## REST response tracing

The MU-plugin also records what WordPress returned after dispatch, including HTTP status, `WP_Error` versus REST response, error information where available, batch response statuses, and IDs of successfully created posts/pages.

This distinguishes an attempted request from a request that actually resulted in content creation.

## Automatic quarantine

When an authenticated user reaches the configured threshold, content created by that user during the active rate-limit window can be automatically quarantined.

By default:

```php
define( 'BRL_DELETE_OFFENDING_CONTENT', true );
define( 'BRL_DELETE_POST_TYPES', array( 'post', 'page' ) );
```

Despite the historical constant name, the plugin **moves offending content to WordPress Trash** rather than permanently deleting it. It verifies the object exists, is an allowed post type, was created during the active window, and still belongs to the offending user.

## Rate limiting

The default threshold is **5 requests / 600 seconds**, tracked independently by source IP and authenticated WordPress user.

If the threshold is reached, the guarded request is blocked. For an authenticated user, the MU-plugin can quarantine qualifying content, invalidate sessions, and send an administrator alert.

## Logs

The default forensic log is:

```text
wp-content/rest-lockdown.log
```

Examples:

```bash
tail -f /path/to/wordpress/wp-content/rest-lockdown.log
grep '/batch/v1' /path/to/wordpress/wp-content/rest-lockdown.log
grep 'BLOCKED' /path/to/wordpress/wp-content/rest-lockdown.log
grep 'trashed offending' /path/to/wordpress/wp-content/rest-lockdown.log
```

## Tracing the source

Correlate the WordPress forensic log with the Apache, LiteSpeed, or Nginx access log. Look for requests such as:

```text
POST /wp-json/batch/v1
POST /wp-json/wp/v2/posts
POST /wp-json/wp/v2/pages
POST /wp-json/wp/v2/media
```

Correlate timestamp, source IP, HTTP method, request path, HTTP status, WordPress user, and trace ID.

This helps distinguish an external HTTP request from WordPress-internal execution, WP-Cron activity, or evidence requiring deeper server investigation.

**Important:** the MU-plugin cannot by itself prove that malware or a server backdoor exists. If internal execution is suspected, inspect filesystem, database, PHP, Cron, authentication, and web-server logs as well.

## Cloudflare

Only enable:

```php
define( 'BRL_BEHIND_CLOUDFLARE', true );
```

when the WordPress origin is actually proxied through Cloudflare and the proxy configuration is understood. Do not enable it merely because the domain uses Cloudflare DNS.

## IP allowlist

To restrict guarded REST writes to known IP addresses:

```php
define( 'BRL_ALLOWED_IPS', array(
    '123.45.67.89',
) );
```

Be careful with changing residential or mobile IP addresses.

## Optional request-body tracing

Request-body tracing is disabled by default:

```php
define( 'BRL_TRACE_BODY', false );
```

If temporarily enabled, use it only during forensic investigation and review the resulting logs for sensitive information. Disable it again after the investigation.

## Admin attribution

Because this is a MU-plugin, there is no activation event. When the MU-plugin is loaded, it adds a discreet **REST Lockdown by MENJ** attribution link to the **WordPress administration footer**. It does not inject a hidden backlink into the public site's HTML.

The attribution links to **https://menj.blog**.

## Incident response

If suspicious REST activity is detected:

1. Preserve existing logs.
2. Identify the affected WordPress account.
3. Reset the account password.
4. Review administrator accounts.
5. Review Application Passwords and authentication mechanisms.
6. Review recently created and modified posts/pages.
7. Review the WordPress Trash for quarantined content.
8. Inspect plugins, themes, and MU-plugins for unexpected files or code.
9. Inspect recently modified PHP files.
10. Review database changes.
11. Correlate WordPress traces with web-server access logs.
12. Review PHP, Cron, SSH/SFTP, FTP, and hosting control-panel logs where available.
13. Investigate possible malware or persistent backdoors.
14. Fix the underlying vulnerability.

Do not assume that `/batch/v1` activity proves a server backdoor. Conversely, a REST attack does not rule one out.

## Removal

After the incident has been investigated and remediated, back up the configuration and forensic logs, then remove:

```text
wp-content/mu-plugins/rest-lockdown.php
```

There is no Deactivate button for a MU-plugin. Removing the file stops WordPress from loading it on subsequent requests.

## License

REST Lockdown 1.0.0 is licensed under the **GNU General Public License, version 3 or later (GPL-3.0-or-later)**.

See [LICENSE.md](LICENSE.md).
