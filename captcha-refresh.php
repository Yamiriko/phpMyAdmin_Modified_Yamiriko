<?php

declare(strict_types=1);

$rootPath = __DIR__ . DIRECTORY_SEPARATOR;

if (! defined('ROOT_PATH')) {
    define('ROOT_PATH', $rootPath);
}

if (! defined('PHPMYADMIN')) {
    define('PHPMYADMIN', true);
}

require_once ROOT_PATH . 'libraries/constants.php';

if (! @is_readable(AUTOLOAD_FILE)) {
    http_response_code(500);
    echo json_encode(['error' => 'Autoloader not found']);
    exit;
}

require_once AUTOLOAD_FILE;

use PhpMyAdmin\Captcha\Captcha;

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Security headers
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: same-origin');

// Rate limiting: max 20 refresh per minute per session
$rateKey = 'pma_captcha_refresh_count';
$rateTimeKey = 'pma_captcha_refresh_time';

if (! isset($_SESSION[$rateTimeKey]) || (time() - $_SESSION[$rateTimeKey]) > 60) {
    $_SESSION[$rateTimeKey] = time();
    $_SESSION[$rateKey] = 0;
}

$_SESSION[$rateKey] = ($_SESSION[$rateKey] ?? 0) + 1;

if ($_SESSION[$rateKey] > 20) {
    http_response_code(429);
    echo json_encode(['success' => false, 'error' => 'Terlalu banyak permintaan. Silakan tunggu sebentar.']);
    exit;
}

$code = Captcha::generate(6);
Captcha::store($code);
$svg = Captcha::renderImage($code);
$token = Captcha::getToken();

// Pastikan session tersimpan sebelum output
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

// Use JSON_HEX_TAG to prevent XSS via </script> injection in JSON responses
echo json_encode([
    'success' => true,
    'svg' => $svg,
    'token' => $token,
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
