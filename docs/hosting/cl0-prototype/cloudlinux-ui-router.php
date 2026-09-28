<?php
/*
 * SNPANEL MANAGED - request router for CloudLinux Manager's UI under PHP's
 * built-in server (snpanel-cloudlinux-ui.service, loopback only, as the
 * unprivileged snpanel-lvem). The panel reverse-proxies /cloudlinux/ here.
 *
 * Why not Apache/mod_lsapi: PHP there runs inside an LVE, and CloudLinux's
 * pam_sulve then prints a banner into every `sudo cloudlinux-cli.py` answer,
 * which the UI cannot parse. A process started by systemd is not in an LVE.
 */

$base = '/var/lib/snpanel-lvemanager';
$prefix = '/cloudlinux/';
$path = rawurldecode((string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH));

// The custom-panel bundle references a locale script it does not ship; the UI
// reads its strings from assets/i18n/*.json.
if (preg_match('#^/cloudlinux/assets(/assets)?/js/locales/[a-z-]+\.js$#', $path)) {
    header('Content-Type: text/javascript');
    echo "// not shipped by CloudLinux for custom panels; strings come from assets/i18n\n";
    return true;
}

if (strpos($path, $prefix) !== 0) {
    http_response_code(404);
    return true;
}
$rel = substr($path, strlen($prefix));
if ($rel === '' || substr($rel, -1) === '/') {
    $rel .= 'index.php';
}

$real = realpath($base . '/' . $rel);
if ($real === false || strpos($real, $base . '/') !== 0 || !is_file($real)
    || basename($real) === 'mock-send-request.php') {
    http_response_code(404);
    return true;
}

// The panel terminates TLS; LveManager.php checks HTTPS for its same-origin
// test and its cookies' Secure flag.
if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['SERVER_PORT'] = '443';
}

if (substr($real, -4) === '.php') {
    $_SERVER['SCRIPT_FILENAME'] = $real;
    $_SERVER['SCRIPT_NAME'] = $prefix . $rel;
    $_SERVER['PHP_SELF'] = $prefix . $rel;
    chdir(dirname($real));
    require $real;
    return true;
}

$types = [
    'css' => 'text/css', 'js' => 'text/javascript', 'json' => 'application/json',
    'svg' => 'image/svg+xml', 'png' => 'image/png', 'gif' => 'image/gif',
    'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'ico' => 'image/x-icon',
    'woff' => 'font/woff', 'woff2' => 'font/woff2', 'ttf' => 'font/ttf',
    'eot' => 'application/vnd.ms-fontobject', 'html' => 'text/html', 'map' => 'application/json',
];
$ext = strtolower(pathinfo($real, PATHINFO_EXTENSION));
header('Content-Type: ' . ($types[$ext] ?? 'application/octet-stream'));
header('Content-Length: ' . filesize($real));
header('Cache-Control: public, max-age=3600');
readfile($real);
return true;
