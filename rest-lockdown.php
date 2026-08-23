<?php
/**
 * Plugin Name: REST Lockdown
 * Description: Emergency measure against unauthorized casino/gambling spam
 *              being posted via the REST API using compromised credentials.
 *              (1) Disables Application Passwords entirely. (2) Rate-limits
 *              REST content-creation by BOTH IP and authenticated user —
 *              closes the "same account, rotating IPs" pattern seen in the
 *              Aug 2026 incident, where IP-only limiting would be evaded.
 *              (3) Guards posts/pages/media/users/comments/batch/app-passwords.
 *              (4) On trip: auto-quarantines (trashes) the offender's recent
 *              posts — tracked per USER, so it still works even if they used
 *              a different IP for every single request — kills their
 *              sessions, and emails an alert. (5) Optional forensic REST
 *              request/response tracer (always independent of #4 — turning
 *              off tracing never disables quarantine). (6) Disables
 *              content-mutating XML-RPC methods.
 *              REMOVE once root cause (leaked/weak password, missing 2FA)
 *              is fixed — this is a stopgap, not a permanent fix.
 * Version:     4.0
 *
 * Changelog vs the 1.0.0 draft this was merged from:
 * - FIX: quarantine was keyed by (user+IP) pair, so it silently found and
 *   trashed nothing whenever the offender used a different IP for the
 *   request that tripped the cap than for the requests that created the
 *   spam. Now keyed per identifier (ip:x / user:y) matching the rate
 *   limiter itself, and a trip on ANY identifier quarantines everything
 *   recorded under ALL of that request's identifiers. Verified against a
 *   simulated 6-different-IPs/1-account burst.
 * - FIX: quarantine tracking was only ever invoked from inside the
 *   forensic tracer, gated behind BRL_TRACE_REST/BRL_TRACE_RESPONSES —
 *   disabling tracing silently disabled auto-trash too. Split into its
 *   own always-on hook.
 * - FIX: BRL_RATE_LIMIT_MAX restored to 3 (was reverted to 5).
 * - FIX: BRL_TRACE_RETENTION was defined but never used anywhere — the
 *   trace log grew unbounded. Now enforced via a daily WP-Cron trim.
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
if ( ! defined( 'BRL_RATE_LIMIT_MAX' ) )    define( 'BRL_RATE_LIMIT_MAX', 3 );
if ( ! defined( 'BRL_RATE_LIMIT_WINDOW' ) ) define( 'BRL_RATE_LIMIT_WINDOW', 600 ); // seconds

// When the threshold is tripped, trash content created by the offending
// identifier (IP or user) during the current rate-limit window. Trashing
// (not permanent delete) so a false positive is recoverable.
if ( ! defined( 'BRL_DELETE_OFFENDING_CONTENT' ) ) define( 'BRL_DELETE_OFFENDING_CONTENT', true );
if ( ! defined( 'BRL_DELETE_POST_TYPES' ) )         define( 'BRL_DELETE_POST_TYPES', array( 'post', 'page' ) );

// When a user trips the rate limit: force-logout that user everywhere
// (invalidates all their sessions/cookies) and email the site admin.
if ( ! defined( 'BRL_AUTO_KILL_SESSION' ) ) define( 'BRL_AUTO_KILL_SESSION', true );
if ( ! defined( 'BRL_ALERT_EMAIL' ) )       define( 'BRL_ALERT_EMAIL', 'contact@menj.org' );
if ( ! defined( 'BRL_ALERT_COOLDOWN' ) )    define( 'BRL_ALERT_COOLDOWN', 900 ); // don't spam inbox

// Log file for blocked attempts (inside wp-content; not linked/served).
if ( ! defined( 'BRL_LOG_FILE' ) ) define( 'BRL_LOG_FILE', WP_CONTENT_DIR . '/rest-lockdown.log' );

// Forensic REST tracing — purely diagnostic, logs request/response metadata.
// Independent of quarantine/rate-limiting: turning this OFF still leaves
// rate-limiting, auto-trash, session-kill, and alert email fully working.
if ( ! defined( 'BRL_TRACE_REST' ) )      define( 'BRL_TRACE_REST', true );
if ( ! defined( 'BRL_TRACE_BODY' ) )      define( 'BRL_TRACE_BODY', false );
if ( ! defined( 'BRL_TRACE_BODY_MAX' ) )  define( 'BRL_TRACE_BODY_MAX', 1000 );
if ( ! defined( 'BRL_TRACE_RETENTION' ) ) define( 'BRL_TRACE_RETENTION', 7 * DAY_IN_SECONDS );
if ( ! defined( 'BRL_TRACE_RESPONSES' ) ) define( 'BRL_TRACE_RESPONSES', true );
if ( ! defined( 'BRL_TRACE_HEADERS' ) )   define( 'BRL_TRACE_HEADERS', false );
// WAF/edge protection: this plugin cannot configure an external WAF such as
// Cloudflare from inside WordPress. It can, however, enforce the same
// /batch/v1 protection at the WordPress layer and expose a ready-to-copy
// WAF rule pattern in the plugin comments below.
if ( ! defined( 'BRL_BLOCK_BATCH_ENDPOINT' ) ) define( 'BRL_BLOCK_BATCH_ENDPOINT', true );
if ( ! defined( 'BRL_CONTENT_SCAN_ENABLED' ) ) define( 'BRL_CONTENT_SCAN_ENABLED', true );
if ( ! defined( 'BRL_CONTENT_SCAN_POST_TYPES' ) ) define( 'BRL_CONTENT_SCAN_POST_TYPES', array( 'post', 'page' ) );
if ( ! defined( 'BRL_CLEANUP_EXISTING_SPAM' ) ) define( 'BRL_CLEANUP_EXISTING_SPAM', true );
if ( ! defined( 'BRL_CLEANUP_BATCH_SIZE' ) ) define( 'BRL_CLEANUP_BATCH_SIZE', 100 );
if ( ! defined( 'BRL_CLEANUP_ACTION' ) ) define( 'BRL_CLEANUP_ACTION', 'trash' );



/* ============================================================
 * 1. Disable Application Passwords entirely.
 *    Blocks BOTH creating new ones AND authenticating with any that
 *    already exist — WP core checks this filter before either action.
 * ============================================================ */
add_filter( 'wp_is_application_passwords_available', '__return_false' );

/* ============================================================
 * 2. Hooks.
 *    rest_pre_dispatch: forensic trace (always, if enabled) -> the guard
 *    (rate limit / IP allowlist / app-passwords block).
 *    rest_post_dispatch: content-creation tracking (ALWAYS ON, independent
 *    of tracing) -> forensic response trace (only if enabled).
 * ============================================================ */
add_filter( 'rest_pre_dispatch', 'brl_trace_rest_request', 5, 3 );
add_filter( 'rest_pre_dispatch', 'brl_guard_rest_writes', 10, 3 );
add_filter( 'rest_post_dispatch', 'brl_track_created_content_from_response', 20, 3 );
add_filter( 'rest_post_dispatch', 'brl_trace_rest_response', 999, 3 );
add_filter( 'rest_pre_insert_post', 'brl_scan_rest_content', 10, 2 );
add_filter( 'rest_pre_insert_page', 'brl_scan_rest_content', 10, 2 );
add_filter( 'wp_insert_post_data', 'brl_scan_save_data', 10, 2 );


/**
 * Forensic REST trace (request side). Purely diagnostic — see BRL_TRACE_REST.
 * Deliberately does NOT log Authorization, Cookie, or other credential
 * headers. Request bodies are disabled by default.
 */
function brl_trace_rest_request( $result, $server, $request ) {
    if ( ! BRL_TRACE_REST ) {
        return $result;
    }

    $method = strtoupper( $request->get_method() );
    $route  = $request->get_route();

    if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true )
        && ! preg_match( '#^/batch/v1(?:/|$)#', $route ) ) {
        return $result;
    }

    $ip   = brl_get_ip();
    $uid  = get_current_user_id();
    $user = $uid ? get_userdata( $uid ) : false;

    $record = array(
        'event'         => 'REST_TRACE',
        'trace_id'      => wp_generate_uuid4(),
        'ip'            => $ip,
        'method'        => $method,
        'route'         => $route,
        'request_uri'   => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
        'user_id'       => $uid,
        'user_login'    => $user ? $user->user_login : '',
        'authenticated' => $uid ? true : false,
        'remote_addr'   => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
        'user_agent'    => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
        'referer'       => isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '',
        'content_type'  => isset( $_SERVER['CONTENT_TYPE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) : '',
        'content_len'   => isset( $_SERVER['CONTENT_LENGTH'] ) ? absint( $_SERVER['CONTENT_LENGTH'] ) : 0,
        'server_name'   => isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '',
        'source'        => ! empty( $_SERVER['REMOTE_ADDR'] ) ? 'http_request' : 'no_remote_addr',
        'is_cli'        => ( PHP_SAPI === 'cli' ),
        'doing_cron'    => function_exists( 'wp_doing_cron' ) ? wp_doing_cron() : false,
        'rest_route'    => $route,
    );

    if ( BRL_TRACE_HEADERS ) {
        $record['headers'] = array(
            'x_forwarded_for'  => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) : '',
            'x_real_ip'        => isset( $_SERVER['HTTP_X_REAL_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) : '',
            'cf_connecting_ip' => isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) : '',
            'host'             => isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : '',
        );
    }

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
 * Content-creation tracking — ALWAYS ON, independent of BRL_TRACE_REST.
 * This is what quarantine relies on; it must not be gated behind a
 * "just logging" toggle. Reads the created object's ID straight from the
 * actual REST response body (more precise than guessing via save_post —
 * can't misattribute a side-effect post created by another plugin during
 * the same request).
 */
function brl_track_created_content_from_response( $response, $server, $request ) {
    if ( ! BRL_DELETE_OFFENDING_CONTENT ) {
        return $response;
    }
    if ( ! ( $response instanceof WP_HTTP_Response ) ) {
        return $response; // WP_Error-shaped results have nothing to track
    }

    $status = absint( $response->get_status() );
    if ( $status < 200 || $status >= 300 ) {
        return $response;
    }

    $route = $request->get_route();
    $type  = brl_route_post_type( $route );
    if ( ! $type ) {
        return $response;
    }

    $data = $response->get_data();
    if ( ! is_array( $data ) || ! isset( $data['id'] ) || ! is_numeric( $data['id'] ) ) {
        return $response;
    }

    $ip  = brl_get_ip();
    $uid = get_current_user_id();

    // Track under every identifier this rate-limits by, matching
    // brl_guard_rest_writes exactly, so quarantine (which is triggered by
    // whichever identifier trips first) can always find it regardless of
    // which IP the offender happens to be on when the cap is hit.
    $identifiers = array( "ip:$ip" );
    if ( $uid ) {
        $identifiers[] = "user:$uid";
    }

    foreach ( $identifiers as $id ) {
        brl_track_created_content( $id, absint( $data['id'] ), $type, $uid, $ip );
    }

    return $response;
}

/**
 * Forensic REST trace (response side). Purely diagnostic — see
 * BRL_TRACE_REST / BRL_TRACE_RESPONSES. Content tracking for quarantine
 * purposes happens in brl_track_created_content_from_response() above,
 * on a separate always-on hook — turning this OFF never disables it.
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
        // Note: by the time WordPress core fires rest_post_dispatch, a
        // WP_Error returned earlier (e.g. from our own guard) has already
        // been converted to a WP_REST_Response by rest_convert_error_to_response().
        // This branch is kept as defensive/future-proofing; in practice the
        // WP_HTTP_Response branch below is what actually records blocked
        // requests' status codes (403/429 etc).
        'result' => is_wp_error( $response ) ? 'WP_Error' : 'WP_REST_Response',
    );

    if ( is_wp_error( $response ) ) {
        $record['error_code']    = $response->get_error_code();
        $record['error_message'] = sanitize_text_field( $response->get_error_message() );
        $data = $response->get_error_data();
        if ( is_array( $data ) && isset( $data['status'] ) ) {
            $record['status'] = absint( $data['status'] );
        }
    } elseif ( $response instanceof WP_HTTP_Response ) {
        $record['status'] = absint( $response->get_status() );

        if ( $record['status'] >= 200 && $record['status'] < 300 ) {
            $data = $response->get_data();
            if ( is_array( $data ) && isset( $data['id'] ) && is_numeric( $data['id'] ) ) {
                $type = brl_route_post_type( $route );
                if ( $type ) {
                    $record['created_object_id'] = absint( $data['id'] );
                    $record['created_post_type'] = $type;
                }
            }
        }
    }

    if ( preg_match( '#^/batch/v1(?:/|$)#', $route ) && $response instanceof WP_HTTP_Response ) {
        $data = $response->get_data();
        if ( is_array( $data ) ) {
            $record['batch_response_count']    = count( $data );
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
        'json_valid'    => false,
        'request_count' => 0,
        'requests'      => array(),
    );

    if ( ! is_string( $body ) || $body === '' ) {
        return $summary;
    }

    $decoded = json_decode( $body, true );
    if ( ! is_array( $decoded ) || empty( $decoded['requests'] ) || ! is_array( $decoded['requests'] ) ) {
        return $summary;
    }

    $summary['json_valid']    = true;
    $summary['request_count'] = count( $decoded['requests'] );

    foreach ( $decoded['requests'] as $sub ) {
        if ( ! is_array( $sub ) ) {
            continue;
        }
        $item = array(
            'method' => isset( $sub['method'] ) ? strtoupper( sanitize_text_field( $sub['method'] ) ) : '',
            'path'   => isset( $sub['path'] ) ? sanitize_text_field( $sub['path'] ) : '',
        );
        if ( isset( $sub['body'] ) && is_array( $sub['body'] ) ) {
            $safe_keys = array();
            foreach ( array_keys( $sub['body'] ) as $key ) {
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
        $body     = wp_json_encode( $redacted );
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
        'authorization', 'cookie', 'nonce', 'secret', 'api_key', 'apikey',
    );
    if ( is_array( $value ) ) {
        $out = array();
        foreach ( $value as $key => $item ) {
            $normalized = strtolower( preg_replace( '/[^a-z0-9_]/i', '', (string) $key ) );
            $out[ $key ] = in_array( $normalized, $sensitive, true ) ? '[REDACTED]' : brl_trace_redact_array( $item );
        }
        return $out;
    }
    return $value;
}

function brl_trace_log( $record ) {
    // Same timestamp format as brl_log() below — brl_trim_log() parses both.
    $line = '[' . gmdate( 'd-M-Y H:i:s' ) . ' UTC] ' . wp_json_encode( $record ) . PHP_EOL;
    @error_log( $line, 3, BRL_LOG_FILE );
}

/* ============================================================
 * 3. Content anti-gambling/SEO-spam scanner.
 * ============================================================ */
function brl_gambling_match( $text ) {
    $text = html_entity_decode( (string) $text, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
    $rules = array(
        'gambling-link' => '/<a\b[^>]*href\s*=\s*["\'][^"\']*(?:casino|bet|bets|betting|gambl|slot|poker|jackpot|roulette|blackjack)[^"\']*["\'][^>]*>/i',
        'gambling-anchor' => '/<a\b[^>]*>[^<]*(?:casino|betting|gambling|jackpot|roulette|blackjack|poker|slots?)\b[^<]*<\/a>/is',
        'hidden-gambling' => '/(?:left\s*:\s*-\s*\d+px|top\s*:\s*-\s*\d+px|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|opacity\s*:\s*0)[^>]*>.*?(?:casino|betting|gambling|jackpot|roulette|blackjack|poker|slots?)/is',
        'gambling-cluster' => '/\b(?:casino|casinos|betting|sportsbook|jackpot|roulette|blackjack|poker|slots?|wager|odds|bookmaker|bookie|gambling|bet\s+online|online\s+casino)\b/i'
    );
    foreach ( $rules as $name => $regex ) {
        if ( preg_match( $regex, $text ) ) {
            if ( 'gambling-cluster' === $name ) {
                $n = preg_match_all('/\b(?:casino|betting|sportsbook|jackpot|roulette|blackjack|poker|slots?|wager|bookmaker|gambling)\b/i', $text);
                if ( $n < 2 && ! preg_match('/<a\b[^>]+href\s*=/i', $text) ) continue;
            }
            return $name;
        }
    }
    return false;
}
function brl_strip_gambling_injection( $content ) {
    $patterns = array(
        '/<a\b[^>]*href\s*=\s*["\'][^"\']*(?:casino|bet|bets|betting|gambl|slot|poker|jackpot|roulette|blackjack)[^"\']*["\'][^>]*>.*?<\/a>/is',
        '/<([a-z0-9]+)\b[^>]*style\s*=\s*["\'][^"\']*(?:left\s*:\s*-\s*\d+px|top\s*:\s*-\s*\d+px|display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?)[^"\']*["\'][^>]*>.*?(?:casino|betting|gambling|jackpot|roulette|blackjack|poker|slots?).*?<\/\1>/is'
    );
    foreach ( $patterns as $pattern ) $content = preg_replace( $pattern, '', (string) $content );
    return $content;
}
function brl_scan_rest_content( $prepared, $request ) {
    if ( ! BRL_CONTENT_SCAN_ENABLED || ! is_object( $prepared ) ) return $prepared;
    $text = ( $prepared->post_title ?? '' ) . "\n" . ( $prepared->post_content ?? '' ) . "\n" . ( $prepared->post_excerpt ?? '' );
    $match = brl_gambling_match( $text );
    if ( ! $match ) return $prepared;
    brl_log( 'BLOCKED (gambling content): ' . brl_get_ip() . ' -> ' . $request->get_method() . ' ' . $request->get_route() . ' | rule=' . $match );
    return new WP_Error( 'brl_gambling_spam_blocked', 'The submitted content was rejected by the site security filter.', array( 'status' => 403 ) );
}
function brl_scan_save_data( $data, $postarr ) {
    if ( ! BRL_CONTENT_SCAN_ENABLED ) return $data;
    $type = isset($data['post_type']) ? sanitize_key($data['post_type']) : '';
    if ( ! in_array($type, BRL_CONTENT_SCAN_POST_TYPES, true) ) return $data;
    $text = ($data['post_title'] ?? '') . "\n" . ($data['post_content'] ?? '') . "\n" . ($data['post_excerpt'] ?? '');
    $match = brl_gambling_match($text);
    if (!$match) return $data;
    $id = isset($postarr['ID']) ? absint($postarr['ID']) : 0;
    brl_log("BLOCKED (save-boundary gambling scan): post_type=$type post_id=$id rule=$match");
    $data['post_title'] = brl_strip_gambling_injection($data['post_title'] ?? '');
    $data['post_content'] = brl_strip_gambling_injection($data['post_content'] ?? '');
    $data['post_excerpt'] = brl_strip_gambling_injection($data['post_excerpt'] ?? '');
    return $data;
}
function brl_cleanup_existing_gambling_spam() {
    if ( ! BRL_CLEANUP_EXISTING_SPAM ) return 0;
    $ids = get_posts(array('post_type'=>BRL_CONTENT_SCAN_POST_TYPES,'post_status'=>'any','posts_per_page'=>BRL_CLEANUP_BATCH_SIZE,'fields'=>'ids','orderby'=>'ID','order'=>'DESC'));
    $count = 0;
    foreach ($ids as $id) {
        $p = get_post($id); if (!$p) continue;
        $match = brl_gambling_match($p->post_title."\n".$p->post_content."\n".$p->post_excerpt);
        if (!$match) continue;
        if ('delete' === BRL_CLEANUP_ACTION) wp_delete_post($id, true); else wp_trash_post($id);
        brl_log("ACTION: quarantined existing gambling content ID $id | rule=$match"); $count++;
    }
    return $count;
}
register_activation_hook(__FILE__, 'brl_cleanup_existing_gambling_spam');
add_action('brl_daily_gambling_scan', 'brl_cleanup_existing_gambling_spam');
if (!wp_next_scheduled('brl_daily_gambling_scan')) wp_schedule_event(time()+3*HOUR_IN_SECONDS, 'daily', 'brl_daily_gambling_scan');

/* ============================================================
 * 3. The rate-limit / allowlist / app-passwords guard.
 * ============================================================ */
function brl_guard_rest_writes( $result, $server, $request ) {
    $method = strtoupper( $request->get_method() );
    $route  = $request->get_route();

    // CVE-2026-63030 / wp2shell hardening:
    // The WordPress batch endpoint is not needed by most public visitors.
    // Block unauthenticated POSTs to /batch/v1 at the WordPress layer.
    //
    // IMPORTANT: This is a defence-in-depth measure, not a replacement for
    // keeping WordPress Core patched. A real WAF should ideally enforce the
    // same rule before PHP/WordPress is reached.
    if (
        BRL_BLOCK_BATCH_ENDPOINT
        && 'POST' === $method
        && preg_match( '#^/batch/v1(?:/|$)#', $route )
        && ! is_user_logged_in()
    ) {
        brl_log( 'BLOCKED (unauthenticated batch endpoint): ' . brl_get_ip() . " -> $method $route" );
        return new WP_Error(
            'brl_batch_blocked',
            'This endpoint is not available.',
            array( 'status' => 403 )
        );
    }

    if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) ) {
        return $result; // only guard writes; reads are unaffected
    }

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
            // Quarantine using ALL of this request's identifiers, not just
            // the one that tripped — the offender's prior posts may be
            // filed under "ip:1.2.3.4" from an earlier request while THIS
            // request comes from a brand-new "ip:5.6.7.8". The "user:$uid"
            // bucket (present on every authenticated request regardless of
            // IP) is what actually catches a rotating-IP burst.
            brl_quarantine_offending_content( $identifiers, $uid );
            brl_respond_to_trip( $identifiers, $uid, $ip, $route );
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
 * 4. Content tracking + quarantine.
 * ============================================================ */

function brl_route_post_type( $route ) {
    if ( preg_match( '#^/wp/v2/(posts|pages)(?:/|$)#', $route, $m ) ) {
        return ( 'pages' === $m[1] ) ? 'page' : 'post';
    }
    return false;
}

/**
 * Record a created post ID under a given identifier ("ip:x" or "user:y").
 * Called once per identifier that applies to the request (see
 * brl_track_created_content_from_response above).
 */
function brl_track_created_content( $identifier, $post_id, $post_type, $uid, $ip ) {
    $key   = 'brl_created_' . md5( $identifier );
    $items = get_transient( $key );
    $items = is_array( $items ) ? $items : array();

    $items[] = array(
        'id'         => absint( $post_id ),
        'post_type'  => sanitize_key( $post_type ),
        'user_id'    => absint( $uid ),
        'ip'         => sanitize_text_field( $ip ),
        'created_at' => time(),
    );

    $cutoff = time() - BRL_RATE_LIMIT_WINDOW;
    $items  = array_values( array_filter( $items, function ( $item ) use ( $cutoff ) {
        return isset( $item['created_at'] ) && $item['created_at'] >= $cutoff;
    } ) );

    set_transient( $key, $items, BRL_RATE_LIMIT_WINDOW );
}

/**
 * Quarantine content created during the active attack window, across ALL
 * identifiers tied to the request that tripped the cap (not just the one
 * that tripped it — see the call site in brl_guard_rest_writes for why).
 * We trash rather than permanently delete so the administrator can recover
 * legitimate content if the threshold was triggered incorrectly.
 */
function brl_quarantine_offending_content( $identifiers, $uid ) {
    if ( ! BRL_DELETE_OFFENDING_CONTENT ) {
        return;
    }

    $cutoff       = time() - BRL_RATE_LIMIT_WINDOW;
    $seen_post_ids = array();
    $trashed       = 0;

    foreach ( $identifiers as $identifier ) {
        $key   = 'brl_created_' . md5( $identifier );
        $items = get_transient( $key );
        if ( ! is_array( $items ) ) {
            continue;
        }

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
            $post_id = absint( $item['id'] );
            if ( isset( $seen_post_ids[ $post_id ] ) ) {
                continue; // already processed via another identifier
            }
            $seen_post_ids[ $post_id ] = true;

            $post = get_post( $post_id );
            if ( ! $post || $post->post_type !== $item['post_type'] ) {
                continue;
            }

            // Only quarantine content still owned by the offending user —
            // prevents an unrelated administrator's content being trashed.
            // If the trip was IP-only (no authenticated user, $uid === 0),
            // skip the author check entirely (nothing to compare against).
            if ( $uid && absint( $post->post_author ) !== absint( $uid ) ) {
                continue;
            }

            if ( wp_trash_post( $post_id ) ) {
                $trashed++;
                brl_log( "ACTION: trashed offending {$post->post_type} ID {$post_id} (identifier: {$identifier})" );
            }
        }

        delete_transient( $key ); // clear so we don't re-process the same IDs next trip
    }

    brl_log( 'ACTION: quarantined ' . $trashed . ' offending content item(s) for [' . implode( ', ', $identifiers ) . ']' );
}

/* ============================================================
 * 5. On a tripped limit: kill sessions (if authenticated) and email an
 *    alert, throttled so a burst of blocked requests only sends one email.
 * ============================================================ */
function brl_respond_to_trip( $identifiers, $uid, $ip, $route ) {
    $cooldown_key = 'brl_alert_' . md5( implode( '|', $identifiers ) );
    if ( get_transient( $cooldown_key ) ) {
        return; // already alerted/handled recently for this offender
    }
    set_transient( $cooldown_key, 1, BRL_ALERT_COOLDOWN );

    $login = '';
    if ( $uid ) {
        $user  = get_userdata( $uid );
        $login = $user ? $user->user_login : "uid:$uid";
        if ( BRL_AUTO_KILL_SESSION ) {
            WP_Session_Tokens::get_instance( $uid )->destroy_all();
            brl_log( "ACTION: killed all sessions for user '{$login}' (uid {$uid}) after rate-limit trip from $ip" );
        }
    }

    if ( BRL_ALERT_EMAIL ) {
        $body  = 'Offender: ' . implode( ', ', $identifiers ) . " (IP {$ip}" . ( $login ? ", user '{$login}'" : '' ) . ")\n";
        $body .= "Route: {$route}\n\n";
        if ( $login && BRL_AUTO_KILL_SESSION ) {
            $body .= "User '{$login}' has been force-logged-out of all sessions.\n\n";
        }
        if ( BRL_DELETE_OFFENDING_CONTENT ) {
            $body .= "Content created by this offender during the active rate-limit window has been automatically moved to Trash (not permanently deleted). Check the log below for exactly which post IDs.\n\n";
        }
        $body .= "Recommended: reset this user's password now and review recently published content.\n\n";
        $body .= 'Log: ' . BRL_LOG_FILE;

        wp_mail(
            BRL_ALERT_EMAIL,
            'REST Lockdown: content-spam rate limit tripped on ' . home_url(),
            $body
        );
    }
}

/* ============================================================
 * 6. Disable XML-RPC pingback + content-mutation methods.
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
 * 7. Log retention — BRL_TRACE_RETENTION was previously defined but never
 *    enforced, so the trace log grew unbounded. A daily WP-Cron job now
 *    trims lines older than the retention window.
 * ============================================================ */
add_action( 'brl_trim_log_event', 'brl_trim_log' );

if ( ! wp_next_scheduled( 'brl_trim_log_event' ) ) {
    wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'brl_trim_log_event' );
}

function brl_trim_log() {
    if ( ! file_exists( BRL_LOG_FILE ) || ! is_readable( BRL_LOG_FILE ) || ! is_writable( BRL_LOG_FILE ) ) {
        return;
    }
    $cutoff = time() - BRL_TRACE_RETENTION;
    $kept   = array();

    $handle = @fopen( BRL_LOG_FILE, 'r' );
    if ( ! $handle ) {
        return;
    }
    while ( ( $line = fgets( $handle ) ) !== false ) {
        if ( preg_match( '/^\[(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}) UTC\]/', $line, $m ) ) {
            $ts = strtotime( $m[1] . ' UTC' );
            if ( $ts !== false && $ts < $cutoff ) {
                continue; // drop lines older than the retention window
            }
        }
        $kept[] = $line;
    }
    fclose( $handle );

    @file_put_contents( BRL_LOG_FILE, implode( '', $kept ) );
}

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
    $line = '[' . gmdate( 'd-M-Y H:i:s' ) . " UTC] {$message}" . PHP_EOL;
    @error_log( $line, 3, BRL_LOG_FILE );
}


/* ============================================================
 * 8. WAF RULE — configure this OUTSIDE WordPress as well.
 *
 * This PHP plugin cannot create a Cloudflare/server WAF rule.
 * Recommended edge rule:
 *
 *   IF:
 *     http.request.method eq "POST"
 *     AND (
 *       starts_with(http.request.uri.path, "/wp-json/batch/v1")
 *       OR http.request.uri.query contains "rest_route=/batch/v1"
 *     )
 *
 *   THEN:
 *     Block
 *
 * If legitimate integrations on this site require the batch endpoint,
 * use a narrower rule or allowlist those trusted sources instead.
 *
 * WordPress Core must remain patched. The WAF rule is defence-in-depth.
 * ============================================================ */
