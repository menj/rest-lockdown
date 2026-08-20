<?php
/**
 * Plugin Name: REST Lockdown
 * Plugin URI:    https://github.com/menj/rest-lockdown
 * Description: Emergency measure against unauthorized casino/gambling spam
 *              being posted via the REST API using compromised credentials.
 *              (1) Disables Application Passwords entirely. (2) Rate-limits
 *              REST content-creation by BOTH IP and authenticated user —
 *              closes the "same account, rotating IPs" pattern seen in the
 *              Aug 2026 incident, where IP-only limiting would be evaded.
 *              (3) Guards posts/pages/media/users/comments/batch/app-passwords.
 *              (4) On trip: kills the user's sessions + emails an alert.
 *              (5) Disables content-mutating XML-RPC methods.
 *              REMOVE once root cause (leaked/weak password, missing 2FA)
 *              is fixed — this is a stopgap, not a permanent fix.
 * Version:     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) exit;

/* ============================================================
 * CONFIG — edit these values as needed
 * ============================================================ */

// Optional hard IP allowlist for REST content creation.
// Leave EMPTY to skip IP-gating and rely on rate-limiting only (safer
// default — won't lock you out if your IP changes).
if ( ! defined( 'BRL_ALLOWED_IPS' ) ) {
    define( 'BRL_ALLOWED_IPS', array(
        // '123.45.67.89',
    ) );
}

// Only trust the CF-Connecting-IP header if the site genuinely sits behind
// Cloudflare. Left false, an attacker can spoof that header to fake their
// IP and dodge the allowlist/rate limit. Set true only if you've confirmed
// Cloudflare proxies all traffic to this server.
if ( ! defined( 'BRL_BEHIND_CLOUDFLARE' ) ) {
    define( 'BRL_BEHIND_CLOUDFLARE', false );
}

// Max content-creation REST requests allowed per IP, AND separately per
// logged-in user, within the time window. Whichever limit is hit first
// blocks the request. Per-user matters because the Aug incident used 7
// different source IPs against what was almost certainly one compromised
// account — an IP-only limit doesn't catch that pattern.
if ( ! defined( 'BRL_RATE_LIMIT_MAX' ) )    define( 'BRL_RATE_LIMIT_MAX', 5 );
if ( ! defined( 'BRL_RATE_LIMIT_WINDOW' ) ) define( 'BRL_RATE_LIMIT_WINDOW', 600 ); // seconds

// When the threshold is tripped, optionally trash content created by the
// offending authenticated user during the current rate-limit window.
// Default is true because this plugin is intended as an emergency spam stopgap.
if ( ! defined( 'BRL_DELETE_OFFENDING_CONTENT' ) ) define( 'BRL_DELETE_OFFENDING_CONTENT', true );
if ( ! defined( 'BRL_DELETE_POST_TYPES' ) ) define( 'BRL_DELETE_POST_TYPES', array( 'post', 'page' ) );


// When a user trips the rate limit: force-logout that user everywhere
// (invalidates all their sessions/cookies) and email the site admin.
if ( ! defined( 'BRL_AUTO_KILL_SESSION' ) ) define( 'BRL_AUTO_KILL_SESSION', true );
if ( ! defined( 'BRL_ALERT_EMAIL' ) )       define( 'BRL_ALERT_EMAIL', 'contact@menj.org' );
if ( ! defined( 'BRL_ALERT_COOLDOWN' ) )    define( 'BRL_ALERT_COOLDOWN', 900 ); // don't spam inbox

// Log file for blocked attempts (inside wp-content; not linked/served).
if ( ! defined( 'BRL_LOG_FILE' ) ) define( 'BRL_LOG_FILE', WP_CONTENT_DIR . '/rest-lockdown.log' );

// Forensic REST tracing. Logs request metadata and batch sub-request paths
// without logging passwords/tokens/cookies. Enable body excerpts only when
// actively investigating an incident.
if ( ! defined( 'BRL_TRACE_REST' ) )       define( 'BRL_TRACE_REST', true );
if ( ! defined( 'BRL_TRACE_BODY' ) )       define( 'BRL_TRACE_BODY', false );
if ( ! defined( 'BRL_TRACE_BODY_MAX' ) )   define( 'BRL_TRACE_BODY_MAX', 1000 );
if ( ! defined( 'BRL_TRACE_RETENTION' ) )  define( 'BRL_TRACE_RETENTION', 7 * DAY_IN_SECONDS );
if ( ! defined( 'BRL_TRACE_RESPONSES' ) ) define( 'BRL_TRACE_RESPONSES', true );
if ( ! defined( 'BRL_TRACE_HEADERS' ) )   define( 'BRL_TRACE_HEADERS', false );



/* ============================================================
 * 1. Disable Application Passwords entirely.
 *    Blocks BOTH creating new ones AND authenticating with any that
 *    already exist — WP core checks this filter before either action.
 * ============================================================ */
add_filter( 'wp_is_application_passwords_available', '__return_false' );

/* ============================================================
 * 2. Rate-limit (and optionally IP-gate) REST writes to the routes
 *    that matter: content creation, users, comments, batch, and the
 *    application-passwords endpoint itself (redundant with #1, but
 *    cheap insurance against a future core change).
 * ============================================================ */
add_filter( 'rest_pre_dispatch', 'brl_trace_rest_request', 5, 3 );
add_filter( 'rest_pre_dispatch', 'brl_guard_rest_writes', 10, 3 );
add_filter( 'rest_post_dispatch', 'brl_trace_rest_response', 999, 3 );



/**
 * Forensic REST trace.
 *
 * This runs before the lockdown guard so blocked requests are still captured.
 * It records the source IP as seen by PHP, request metadata, authenticated
 * user (if any), and for /batch/v1 the individual sub-request methods/paths.
 *
 * It deliberately does NOT log Authorization, Cookie, or other credential
 * headers. Request bodies are disabled by default.
 */
/**
 * Admin-only attribution.
 */
add_filter( 'admin_footer_text', 'brl_admin_footer_attribution' );

function brl_admin_footer_attribution( $text ) {
    return $text . ' &nbsp; REST Lockdown by <a href="https://menj.blog" rel="author">MENJ</a>';
}

function brl_trace_rest_request( $result, $server, $request ) {
    if ( ! BRL_TRACE_REST ) {
        return $result;
    }

    $method = strtoupper( $request->get_method() );
    $route  = $request->get_route();

    // Trace writes and batch requests; reads are normally not useful for this incident.
    if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true )
        && ! preg_match( '#^/batch/v1(?:/|$)#', $route ) ) {
        return $result;
    }

    $ip  = brl_get_ip();
    $uid = get_current_user_id();
    $user = $uid ? get_userdata( $uid ) : false;

    $record = array(
        'event'        => 'REST_TRACE',
        'trace_id'     => wp_generate_uuid4(),
        'ip'           => $ip,
        'method'       => $method,
        'route'        => $route,
        'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
        'user_id'      => $uid,
        'user_login'   => $user ? $user->user_login : '',
        'authenticated'=> $uid ? true : false,
        'remote_addr'  => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
        'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
        'referer'      => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
        'content_type' => isset( $_SERVER['CONTENT_TYPE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) : '',
        'content_len'  => isset( $_SERVER['CONTENT_LENGTH'] ) ? absint( $_SERVER['CONTENT_LENGTH'] ) : 0,
        'server_name'  => isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '',
        'source'       => ! empty( $_SERVER['REMOTE_ADDR'] ) ? 'http_request' : 'no_remote_addr',
        'is_cli'        => ( PHP_SAPI === 'cli' ),
        'doing_cron'    => function_exists( 'wp_doing_cron' ) ? wp_doing_cron() : false,
        'rest_route'   => $route,
    );

    if ( BRL_TRACE_HEADERS ) {
        $record['headers'] = array(
            'x_forwarded_for' => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '',
            'x_real_ip'       => isset( $_SERVER['HTTP_X_REAL_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) : '',
            'cf_connecting_ip'=> isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '',
            'host'            => isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '',
        );
    }

    // A batch request is the most important forensic case here.
    if ( preg_match( '#^/batch/v1(?:/|$)#', $route ) ) {
        $body = $request->get_body();
        $record['batch'] = brl_trace_batch_summary( $body );

        if ( BRL_TRACE_BODY && ! empty( $body ) ) {
            $record['body_excerpt'] = brl_trace_redacted_body_excerpt( $body, BRL_TRACE_BODY_MAX );
        }
    } elseif ( BRL_TRACE_BODY && in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
        $body = $request->get_body();
        if ( ! empty( $body ) ) {
            $record['body_excerpt'] = brl_trace_redacted_body_excerpt( $body, BRL_TRACE_BODY_MAX );
        }
    }

    brl_trace_log( $record );

    return $result;
}


/**
 * Capture the REST result after dispatch.
 *
 * This is intentionally separate from the PHP error log: it records whether
 * the REST request actually returned 2xx/3xx/4xx/5xx and whether WordPress
 * returned a WP_Error. For batch requests, this helps distinguish an attempted
 * request from a successful operation.
 */
function brl_trace_rest_response( $response, $server, $request ) {
    if ( ! BRL_TRACE_REST || ! BRL_TRACE_RESPONSES ) {
        return $response;
    }

    $method = strtoupper( $request->get_method() );
    $route  = $request->get_route();

    if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true )
        && ! preg_match( '#^/batch/v1(?:/|$)#', $route ) ) {
        return $response;
    }

    $record = array(
        'event'  => 'REST_RESPONSE',
        'ip'     => brl_get_ip(),
        'method' => $method,
        'route'  => $route,
        'status' => 0,
        'result' => is_wp_error( $response ) ? 'WP_Error' : 'WP_REST_Response',
    );

    if ( is_wp_error( $response ) ) {
        $record['error_code'] = $response->get_error_code();
        $record['error_message'] = sanitize_text_field( $response->get_error_message() );
        $data = $response->get_error_data();
        if ( is_array( $data ) && isset( $data['status'] ) ) {
            $record['status'] = absint( $data['status'] );
        }
    } elseif ( $response instanceof WP_HTTP_Response ) {
        $record['status'] = absint( $response->get_status() );

        // If a content-creation request succeeded, remember the created object
        // so a later threshold trip can quarantine it.
        if ( $record['status'] >= 200 && $record['status'] < 300 ) {
            $data = $response->get_data();
            if ( is_array( $data ) && isset( $data['id'] ) && is_numeric( $data['id'] ) ) {
                $route = $request->get_route();
                $type = brl_route_post_type( $route );
                if ( $type ) {
                    brl_track_created_content(
                        absint( $data['id'] ),
                        $type,
                        get_current_user_id(),
                        brl_get_ip()
                    );
                    $record['created_object_id'] = absint( $data['id'] );
                    $record['created_post_type'] = $type;
                }
            }
        }
    }

    // For batch responses, record only safe structural information.
    if ( preg_match( '#^/batch/v1(?:/|$)#', $route )
        && $response instanceof WP_HTTP_Response ) {
        $data = $response->get_data();
        if ( is_array( $data ) ) {
            $record['batch_response_count'] = count( $data );
            $record['batch_response_statuses'] = array();

            foreach ( $data as $item ) {
                if ( is_array( $item ) && isset( $item['status'] ) ) {
                    $record['batch_response_statuses'][] = absint( $item['status'] );
                }
            }
        }
    }

    brl_trace_log( $record );

    return $response;
}

/**
 * Extract only useful batch forensic information: sub-request method/path
 * and body field names. No credential values are logged.
 */
function brl_trace_batch_summary( $body ) {
    $summary = array(
        'json_valid' => false,
        'request_count' => 0,
        'requests' => array(),
    );

    if ( ! is_string( $body ) || $body === '' ) {
        return $summary;
    }

    $decoded = json_decode( $body, true );
    if ( ! is_array( $decoded ) || empty( $decoded['requests'] ) || ! is_array( $decoded['requests'] ) ) {
        return $summary;
    }

    $summary['json_valid'] = true;
    $summary['request_count'] = count( $decoded['requests'] );

    foreach ( $decoded['requests'] as $sub ) {
        if ( ! is_array( $sub ) ) {
            continue;
        }

        $item = array(
            'method' => isset( $sub['method'] ) ? strtoupper( sanitize_text_field( $sub['method'] ) ) : '',
            'path'   => isset( $sub['path'] ) ? sanitize_text_field( $sub['path'] ) : '',
        );

        // Show which content fields were attempted, without their values.
        if ( isset( $sub['body'] ) && is_array( $sub['body'] ) ) {
            $keys = array_keys( $sub['body'] );
            $safe_keys = array();
            foreach ( $keys as $key ) {
                $safe_keys[] = sanitize_key( $key );
            }
            $item['body_fields'] = array_values( array_filter( $safe_keys ) );
        }

        $summary['requests'][] = $item;
    }

    return $summary;
}

/**
 * Optional body excerpt for active forensic investigation.
 * Redacts common credential fields before logging.
 */
function brl_trace_redacted_body_excerpt( $body, $max ) {
    $decoded = json_decode( $body, true );

    if ( is_array( $decoded ) ) {
        $redacted = brl_trace_redact_array( $decoded );
        $body = wp_json_encode( $redacted );
    }

    $body = preg_replace(
        '/("?(?:password|pass|token|access_token|refresh_token|authorization|cookie|nonce|secret|api[_-]?key)"?\s*:\s*)"[^"]*"/i',
        '$1"[REDACTED]"',
        (string) $body
    );

    return substr( $body, 0, max( 1, absint( $max ) ) );
}

function brl_trace_redact_array( $value ) {
    $sensitive = array(
        'password', 'pass', 'token', 'access_token', 'refresh_token',
        'authorization', 'cookie', 'nonce', 'secret', 'api_key', 'apikey'
    );

    if ( is_array( $value ) ) {
        $out = array();
        foreach ( $value as $key => $item ) {
            $normalized = strtolower( preg_replace( '/[^a-z0-9_]/i', '', (string) $key ) );
            if ( in_array( $normalized, $sensitive, true ) ) {
                $out[ $key ] = '[REDACTED]';
            } else {
                $out[ $key ] = brl_trace_redact_array( $item );
            }
        }
        return $out;
    }

    return $value;
}

function brl_trace_log( $record ) {
    $line = '[' . gmdate( 'Y-m-d H:i:s' ) . " UTC] " . wp_json_encode( $record ) . PHP_EOL;
    @error_log( $line, 3, BRL_LOG_FILE );
}

function brl_guard_rest_writes( $result, $server, $request ) {
    $method = $request->get_method();
    if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
        return $result; // only guard writes; reads are unaffected
    }

    $route = $request->get_route();

    // Application-passwords: always block outright, regardless of
    // allowlist/rate limit — redundant with the filter above by design.
    if ( preg_match( '#^/wp/v2/users/[^/]+/application-passwords#', $route ) ) {
        brl_log( 'BLOCKED (application-passwords route): ' . brl_get_ip() . " -> $method $route" );
        return new WP_Error( 'brl_app_passwords_disabled', 'Application Passwords are disabled.', array( 'status' => 403 ) );
    }

    $guarded_patterns = array(
        '#^/wp/v2/(posts|pages|media|users|comments)(/|$)#',
        '#^/batch/v1(/|$)#',
    );

    $is_guarded = false;
    foreach ( $guarded_patterns as $pattern ) {
        if ( preg_match( $pattern, $route ) ) {
            $is_guarded = true;
            break;
        }
    }
    if ( ! $is_guarded ) {
        return $result;
    }

    $ip  = brl_get_ip();
    $uid = get_current_user_id(); // 0 if not authenticated

    // Optional IP allowlist
    if ( ! empty( BRL_ALLOWED_IPS ) && ! in_array( $ip, BRL_ALLOWED_IPS, true ) ) {
        brl_log( "BLOCKED (IP not allowlisted): $ip -> $method $route" );
        return new WP_Error( 'brl_ip_blocked', 'Content creation is temporarily restricted.', array( 'status' => 403 ) );
    }

    // Rate limit BOTH by IP and by authenticated user — block if either trips.
    $identifiers = array( "ip:$ip" );
    if ( $uid ) {
        $identifiers[] = "user:$uid";
    }

    foreach ( $identifiers as $id ) {
        $key   = 'brl_rl_' . md5( $id );
        $count = (int) get_transient( $key );
        if ( $count >= BRL_RATE_LIMIT_MAX ) {
            brl_log( "BLOCKED (rate limit, {$id}, count={$count}): $ip -> $method $route" );
            if ( $uid ) {
                brl_quarantine_offending_content( $uid, $ip );
                brl_respond_to_trip( $uid, $ip, $route );
            }
            return new WP_Error( 'brl_rate_limited', 'Too many content-creation requests. Try again later.', array( 'status' => 429 ) );
        }
    }
    foreach ( $identifiers as $id ) {
        $key   = 'brl_rl_' . md5( $id );
        $count = (int) get_transient( $key );
        set_transient( $key, $count + 1, BRL_RATE_LIMIT_WINDOW );
    }

    return $result;
}

/* ============================================================
 * 3. On a tripped limit from an authenticated user: kill their
 *    sessions (forces re-login) and email an alert, throttled so
 *    a burst of blocked requests only sends one email.
 * ============================================================ */

function brl_route_post_type( $route ) {
    if ( preg_match( '#^/wp/v2/(posts|pages)(?:/|$)#', $route, $m ) ) {
        return ( 'pages' === $m[1] ) ? 'page' : 'post';
    }
    return false;
}

function brl_track_created_content( $post_id, $post_type, $uid, $ip ) {
    $key = 'brl_created_' . md5( $uid . '|' . $ip );
    $items = get_transient( $key );
    if ( ! is_array( $items ) ) {
        $items = array();
    }

    $items[] = array(
        'id'         => absint( $post_id ),
        'post_type'  => sanitize_key( $post_type ),
        'user_id'    => absint( $uid ),
        'ip'         => sanitize_text_field( $ip ),
        'created_at' => time(),
    );

    // Keep only the current window and avoid unbounded transient growth.
    $cutoff = time() - BRL_RATE_LIMIT_WINDOW;
    $items = array_values( array_filter( $items, function ( $item ) use ( $cutoff ) {
        return isset( $item['created_at'] ) && $item['created_at'] >= $cutoff;
    } ) );

    set_transient( $key, $items, BRL_RATE_LIMIT_WINDOW );
}

/**
 * Quarantine content created during the active attack window.
 *
 * We trash rather than permanently delete so the administrator can recover
 * legitimate content if the threshold was triggered incorrectly.
 */
function brl_quarantine_offending_content( $uid, $ip ) {
    if ( ! BRL_DELETE_OFFENDING_CONTENT ) {
        return;
    }

    $key = 'brl_created_' . md5( $uid . '|' . $ip );
    $items = get_transient( $key );
    if ( ! is_array( $items ) ) {
        return;
    }

    $cutoff = time() - BRL_RATE_LIMIT_WINDOW;
    $trashed = 0;

    foreach ( $items as $item ) {
        if ( empty( $item['id'] ) || empty( $item['post_type'] ) ) {
            continue;
        }
        if ( ! isset( $item['created_at'] ) || $item['created_at'] < $cutoff ) {
            continue;
        }
        if ( ! in_array( $item['post_type'], BRL_DELETE_POST_TYPES, true ) ) {
            continue;
        }

        $post = get_post( absint( $item['id'] ) );
        if ( ! $post || $post->post_type !== $item['post_type'] ) {
            continue;
        }

        // Only quarantine content that is still owned by the offending user.
        // This prevents an unrelated administrator's content being trashed.
        if ( absint( $post->post_author ) !== absint( $uid ) ) {
            continue;
        }

        $result = wp_trash_post( $post->ID );
        if ( $result ) {
            $trashed++;
            brl_log(
                "ACTION: trashed offending {$post->post_type} ID {$post->ID} " .
                "created by user {$uid} from IP {$ip} after rate-limit trip"
            );
        }
    }

    brl_log( "ACTION: quarantined {$trashed} offending content item(s) for user {$uid} / IP {$ip}" );
}

function brl_respond_to_trip( $uid, $ip, $route ) {
    $cooldown_key = 'brl_alert_' . $uid;
    if ( get_transient( $cooldown_key ) ) {
        return; // already alerted/handled recently
    }
    set_transient( $cooldown_key, 1, BRL_ALERT_COOLDOWN );

    $user = get_userdata( $uid );
    $login = $user ? $user->user_login : "uid:$uid";

    if ( BRL_AUTO_KILL_SESSION ) {
        $sessions = WP_Session_Tokens::get_instance( $uid );
        $sessions->destroy_all();
        brl_log( "ACTION: killed all sessions for user '{$login}' (uid {$uid}) after rate-limit trip from $ip" );
    }

    if ( BRL_ALERT_EMAIL ) {
        wp_mail(
            BRL_ALERT_EMAIL,
            'REST Lockdown: content-spam rate limit tripped on ' . home_url(),
            "User '{$login}' (ID {$uid}) tripped the REST content-creation rate limit from IP {$ip} on route {$route}.\n\n" .
            ( BRL_AUTO_KILL_SESSION ? "Their sessions have been force-logged-out automatically.\n\n" : '' ) .
            ( BRL_DELETE_OFFENDING_CONTENT ? "Content created by this user during the active rate-limit window was automatically moved to Trash where it could be safely identified.\n\n" : '' ) .
            "Recommended: reset this user's password now and check Application Passwords / recently published posts.\n\n" .
            'Log: ' . BRL_LOG_FILE
        );
    }
}

/* ============================================================
 * 4. Disable XML-RPC pingback + content-mutation methods.
 *    Read-only / Jetpack-handshake methods are left untouched.
 * ============================================================ */
add_filter( 'xmlrpc_methods', function ( $methods ) {
    $remove = array(
        'pingback.ping',
        'pingback.extensions.getPingbacks',
        'wp.newPost', 'wp.editPost', 'wp.deletePost',
        'wp.newPage', 'wp.newMediaObject',
        'wp.newComment',
        'metaWeblog.newPost', 'metaWeblog.editPost',
        'metaWeblog.newMediaObject',
    );
    foreach ( $remove as $m ) {
        unset( $methods[ $m ] );
    }
    return $methods;
} );

/* ============================================================
 * Helpers
 * ============================================================ */
function brl_get_ip() {
    if ( BRL_BEHIND_CLOUDFLARE && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
        return sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
    }
    if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
        return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
    }
    return 'unknown';
}

function brl_log( $message ) {
    $line = '[' . gmdate( 'Y-m-d H:i:s' ) . " UTC] {$message}" . PHP_EOL;
    @error_log( $line, 3, BRL_LOG_FILE );
}
