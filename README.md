# REST Lockdown

**GitHub:** https://github.com/menj/rest-lockdown

**Emergency WordPress security plugin for REST API content-spam containment and forensic tracing.**

REST Lockdown is a defensive, temporary WordPress plugin designed for incidents involving unauthorized content creation through the WordPress REST API.

## Installation

### Option 1 — WordPress admin

1. Download the `rest-lockdown.php` plugin file.
2. In WordPress, go to **Plugins → Add New Plugin**.
3. Click **Upload Plugin**.
4. Select the `rest-lockdown.php` file.
5. Click **Install Now**.
6. After installation completes, click **Activate Plugin**.

> **Important:** This is an emergency security plugin. Review the configuration near the top of the PHP file before activating it on a production site.

### Option 2 — Upload manually

1. Download the plugin PHP file.
2. Create a directory:

```text
wp-content/plugins/rest-lockdown/
```

3. Upload the PHP file into that directory:

```text
wp-content/plugins/rest-lockdown/rest-lockdown.php
```

4. Log in to WordPress.
5. Go to **Plugins → Installed Plugins**.
6. Find **REST Lockdown**.
7. Click **Activate**.

### Before activation

Make sure you have:

- a working WordPress administrator account;
- access to the server through cPanel, SSH, SFTP or another recovery method;
- a recent backup;
- access to `wp-content/rest-lockdown.log`;
- access to the web-server access logs.

If you are investigating an active compromise, preserve existing logs before making major changes.

## How to use

REST Lockdown is intended to run automatically after activation. There is no separate settings page.

### 1. Review the configuration

Open `rest-lockdown.php` and review the configuration block near the top.

The most important settings are:

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

For an active incident, the recommended starting point is to leave the forensic tracing enabled and keep request-body tracing disabled.

### 2. Activate the plugin

Once configured, activate it from:

**WordPress → Plugins → Installed Plugins → REST Lockdown → Activate**

The protection begins immediately.

### 3. Monitor the forensic log

The default log is:

```text
wp-content/rest-lockdown.log
```

You can inspect it through cPanel File Manager, SSH, SFTP or another server-management tool.

For example, over SSH:

```bash
tail -f /path/to/wordpress/wp-content/rest-lockdown.log
```

To search specifically for REST batch activity:

```bash
grep '"/batch/v1"' /path/to/wordpress/wp-content/rest-lockdown.log
```

To find blocked requests:

```bash
grep 'BLOCKED' /path/to/wordpress/wp-content/rest-lockdown.log
```

To find quarantine actions:

```bash
grep 'trashed offending' /path/to/wordpress/wp-content/rest-lockdown.log
```

### 4. Correlate with the web-server access log

The plugin log tells you what WordPress saw.

The Apache/LiteSpeed/Nginx access log tells you what actually arrived at the web server.

For an incident involving REST abuse, correlate timestamps for:

```text
POST /wp-json/batch/v1
POST /wp-json/wp/v2/posts
POST /wp-json/wp/v2/pages
POST /wp-json/wp/v2/media
```

This is important when determining whether activity originated from an external HTTP client or from an internal process.

### 5. Understand the threshold

The default threshold is:

```text
5 requests / 600 seconds
```

It is enforced separately by:

- source IP; and
- authenticated WordPress user.

If either identity reaches the threshold, the request is blocked.

For an authenticated user who trips the threshold, the plugin can:

1. quarantine content created during the active window;
2. destroy all sessions for that user;
3. send an administrator alert.

### 6. What happens to offending posts/pages

When automatic quarantine is enabled, the plugin tracks successful REST-created posts/pages.

When the authenticated-user threshold is subsequently triggered, qualifying content created during the active rate-limit window is moved to **Trash**.

It is not permanently deleted.

The plugin verifies that the post/page still belongs to the offending user before moving it to Trash.

Review **Posts → Trash** and **Pages → Trash** after an incident.

### 7. Investigate `/batch/v1`

For a batch request, the forensic trace can show:

```text
POST /wp-json/batch/v1
        ↓
authenticated user
        ↓
sub-request count
        ↓
POST /wp/v2/pages
POST /wp/v2/posts
...
        ↓
response status
```

This allows you to distinguish a generic `/batch/v1` probe from an actual attempt to create content.

### 8. Optional body tracing

By default:

```php
define( 'BRL_TRACE_BODY', false );
```

Leave this disabled unless you specifically need request-body evidence.

If temporarily enabled:

```php
define( 'BRL_TRACE_BODY', true );
```

the plugin attempts to redact common credentials and secrets before logging a limited body excerpt.

After the forensic investigation, turn it back off and remove sensitive logs as appropriate.

### 9. Cloudflare configuration

If the site is genuinely behind Cloudflare, you may set:

```php
define( 'BRL_BEHIND_CLOUDFLARE', true );
```

Only do this after confirming that traffic to the origin is actually proxied through Cloudflare.

Do **not** enable this simply because the domain uses Cloudflare DNS. An attacker can otherwise spoof a forwarding header and bypass the intended IP controls.

### 10. Emergency IP allowlist

If you need to restrict REST writes to known trusted IP addresses:

```php
define( 'BRL_ALLOWED_IPS', array(
    '123.45.67.89',
) );
```

Multiple addresses can be specified:

```php
define( 'BRL_ALLOWED_IPS', array(
    '123.45.67.89',
    '203.0.113.10',
) );
```

Leave the array empty if you do not want an IP allowlist.

Be careful with dynamic/residential IP addresses, because an allowlist can lock you out after your public IP changes.

### 11. After an incident

Do not simply leave the plugin as the permanent solution.

Use the containment period to:

1. identify the compromised WordPress account;
2. reset its password;
3. review all administrator accounts;
4. invalidate suspicious sessions;
5. review Application Passwords;
6. inspect recently created content;
7. inspect plugins, themes and MU plugins;
8. inspect recently modified PHP files;
9. review database changes;
10. review Apache/LiteSpeed/Nginx, SSL and FTP/SFTP logs;
11. investigate possible malware or a persistent backdoor;
12. identify and fix the underlying vulnerability.

Only remove REST Lockdown after the underlying cause has been addressed.

---

It combines:

- REST write protection
- IP and authenticated-user rate limiting
- Application Passwords disablement
- REST endpoint guarding
- `/batch/v1` forensic tracing
- source/request metadata logging
- successful REST response tracing
- automatic quarantine of offending posts/pages
- automatic session invalidation
- administrator email alerts
- XML-RPC content-mutation lockdown

> **Important:** This is an emergency containment tool, not a substitute for identifying and fixing the underlying compromise.

## Features

### REST write protection

The plugin monitors and protects REST `POST`, `PUT`, and `PATCH` requests to:

- `/wp/v2/posts`
- `/wp/v2/pages`
- `/wp/v2/media`
- `/wp/v2/users`
- `/wp/v2/comments`
- `/batch/v1`

Application Password endpoints are blocked separately.

### Dual rate limiting

REST content creation is rate-limited independently by:

1. source IP; and
2. authenticated WordPress user.

The first limit reached blocks the request.

This protects against a compromised account using multiple rotating source IPs.

### Forensic REST tracing

Relevant REST requests are logged before the lockdown guard is applied.

The trace records information such as:

- source IP as seen by PHP
- `REMOTE_ADDR`
- HTTP method
- REST route
- request URI
- User-Agent
- Referer
- authenticated user ID/login
- authentication state
- request size and content type
- CLI/cron execution context
- unique trace ID

For `/batch/v1`, the plugin records:

- whether the batch JSON is valid
- number of sub-requests
- sub-request methods
- sub-request paths
- submitted body field names

Credentials and other sensitive values are not logged by default.

### REST response tracing

The plugin also records the result after REST dispatch, including:

- HTTP status
- `WP_Error` versus REST response
- error code/message where applicable
- batch response count and individual response statuses where available
- IDs of successfully created posts/pages

This allows an incident to be reconstructed as:

```text
source IP
    ↓
REST request
    ↓
authenticated user
    ↓
batch/sub-request
    ↓
WordPress response
    ↓
created object or blocked request
```

### Automatic quarantine

When an authenticated user trips the rate limit, content created by that user during the active rate-limit window can be automatically moved to WordPress Trash.

By default this applies to:

- `post`
- `page`

The plugin verifies that the content still belongs to the offending user before moving it to Trash.

It does **not** permanently delete the content.

### Session invalidation

When an authenticated user trips the rate limit, all sessions for that user can be destroyed, forcing re-authentication.

### Email alert

An administrator alert is sent when the authenticated-user rate limit is tripped.

The alert includes:

- username
- user ID
- source IP
- affected REST route
- session invalidation status
- quarantine status
- log location

### XML-RPC lockdown

Content-mutating XML-RPC methods are disabled, including:

- `wp.newPost`
- `wp.editPost`
- `wp.deletePost`
- `wp.newPage`
- `wp.newMediaObject`
- `wp.newComment`
- corresponding MetaWeblog methods
- pingback mutation methods

Read-only and Jetpack-handshake methods are left untouched.

## Configuration

The main configuration is near the top of the plugin.

### IP allowlist

```php
define( 'BRL_ALLOWED_IPS', array() );
```

Leave empty to rely on rate limiting.

If populated, only those IP addresses may perform guarded REST writes.

### Cloudflare

```php
define( 'BRL_BEHIND_CLOUDFLARE', false );
```

Set this to `true` **only after confirming that all traffic reaches the server through Cloudflare**.

The plugin otherwise uses `REMOTE_ADDR` and does not blindly trust spoofable forwarding headers.

### Rate limit

```php
define( 'BRL_RATE_LIMIT_MAX', 5 );
define( 'BRL_RATE_LIMIT_WINDOW', 600 );
```

The default is 5 guarded requests per 600 seconds, independently by IP and authenticated user.

### Automatic quarantine

```php
define( 'BRL_DELETE_OFFENDING_CONTENT', true );
define( 'BRL_DELETE_POST_TYPES', array( 'post', 'page' ) );
```

Despite the historical configuration name, the plugin **moves content to Trash rather than permanently deleting it**.

### Alert email

```php
define( 'BRL_ALERT_EMAIL', 'contact@menj.org' );
```

Change this to the administrator/security address that should receive alerts.

### Logging

```php
define(
    'BRL_LOG_FILE',
    WP_CONTENT_DIR . '/rest-lockdown.log'
);
```

The log is stored inside `wp-content`.

Protect this file from public web access where possible.

### Optional request-body tracing

Request-body tracing is disabled by default:

```php
define( 'BRL_TRACE_BODY', false );
```

Only enable it temporarily during active forensic investigation. Even with redaction, request bodies may contain sensitive material.

## Incident response

If this plugin detects an active REST content-spam incident:

1. Preserve the logs.
2. Do not immediately delete suspicious files.
3. Identify the affected WordPress user.
4. Reset the user's password.
5. Review all administrator accounts.
6. Review Application Passwords and other authentication mechanisms.
7. Inspect recently created and modified content.
8. Inspect plugins, themes, MU plugins and WordPress core for unexpected modifications.
9. Review server access, SSL, FTP/SFTP and authentication logs.
10. Determine whether a persistent backdoor or malware is present.
11. Remove the underlying cause before removing this emergency plugin.

The plugin is intended to **contain the incident while the root cause is investigated**.

## Log interpretation

A typical forensic sequence may look like:

```text
REST_TRACE
    ↓
POST /wp-json/batch/v1
    ↓
external source IP
    ↓
authenticated WordPress user
    ↓
POST /wp/v2/pages
    ↓
REST_RESPONSE
    ↓
201 Created
    ↓
created object ID recorded
    ↓
rate threshold reached
    ↓
request blocked
    ↓
offending content moved to Trash
    ↓
sessions destroyed
    ↓
administrator alert
```

A `403`, `401`, or `429` indicates blocking/failure at the relevant stage. A `201` indicates that the REST request successfully created an object.

## Limitations

REST Lockdown does **not** prove or detect every form of server compromise.

In particular:

- It cannot identify an attacker hidden behind an upstream proxy beyond the IP information available to PHP.
- It cannot determine whether malware exists elsewhere on the filesystem.
- It cannot detect every PHP backdoor.
- It cannot establish that an internal process originated from a particular external attacker.
- It does not replace server-level malware analysis.
- It does not replace database, filesystem, authentication, or access-log investigation.

If there is evidence of a server compromise, perform a broader forensic investigation.

## Temporary nature

This plugin is intentionally designed as an **emergency stopgap**.

Remove it after:

- the compromised credential/account is secured;
- unauthorized sessions are invalidated;
- the underlying vulnerability is fixed;
- suspicious content is reviewed;
- the filesystem and database have been checked;
- server-level persistence has been ruled out or removed.

Do not treat permanent use of restrictive emergency controls as a substitute for remediation.

## Attribution

When active, REST Lockdown adds a discreet **REST Lockdown by MENJ** attribution link to the WordPress administration footer. It does not inject a hidden backlink into the public website.

## Version

Current release: **1.0.0** — first public release.

## License

REST Lockdown is released under the GNU General Public License, version 3 or later.

See [LICENSE.md](LICENSE.md).
