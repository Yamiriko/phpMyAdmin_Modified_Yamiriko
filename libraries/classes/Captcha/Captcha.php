<?php

declare(strict_types=1);

namespace PhpMyAdmin\Captcha;

class Captcha
{
    /**
     * Generate random CAPTCHA code
     */
    public static function generate(int $length = 6): string
    {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $code;
    }

    /**
     * Store CAPTCHA code in session
     */
    public static function store(string $code): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $_SESSION['pma_captcha_code'] = $code;
        $_SESSION['pma_captcha_time'] = time();
        // Generate CSRF-like token for this CAPTCHA
        $_SESSION['pma_captcha_token'] = bin2hex(random_bytes(32));
    }

    /**
     * Get CAPTCHA CSRF token
     */
    public static function getToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        return $_SESSION['pma_captcha_token'] ?? '';
    }

    /**
     * Verify CAPTCHA CSRF token
     */
    public static function verifyToken(string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $stored = $_SESSION['pma_captcha_token'] ?? '';
        if (empty($stored) || empty($token)) {
            return false;
        }
        return hash_equals($stored, $token);
    }

    /**
     * Get stored CAPTCHA code from session
     */
    public static function getStored(): ?string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        return $_SESSION['pma_captcha_code'] ?? null;
    }

    /**
     * Verify user input against stored CAPTCHA
     */
    public static function verify(string $input): bool
    {
        $stored = self::getStored();
        if ($stored === null) {
            return false;
        }

        // Expire after 5 minutes
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $age = time() - ($_SESSION['pma_captcha_time'] ?? 0);
        if ($age > 300) {
            self::destroy();
            return false;
        }

        return strtoupper(trim($input)) === $stored;
    }

    /**
     * Destroy stored CAPTCHA
     */
    public static function destroy(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        unset($_SESSION['pma_captcha_code'], $_SESSION['pma_captcha_time']);
    }

    /**
     * Validate hex color string
     */
    private static function isValidHexColor(string $color): bool
    {
        return preg_match('/^#[0-9a-fA-F]{3,6}$/', $color) === 1;
    }

    /**
     * Render CAPTCHA as SVG image
     */
    public static function renderImage(string $code): string
    {
        $width = 280;
        $height = 60;

        // Background: light theme (matches pmahomme #eee / #fff)
        $bg = '#f5f5f5';

        // Whitelist of allowed colors
        $allowedLineColors = ['#aaa', '#bbb', '#999', '#ccc', '#888'];
        $allowedDotColors = ['#aaa', '#bbb', '#999', '#ccc'];
        $allowedTextColors = ['#444', '#235a81', '#555', '#333', '#2a6496', '#3a3a3a'];

        // Generate noise lines
        $lines = '';
        for ($i = 0; $i < 4; $i++) {
            $x1 = random_int(0, $width);
            $y1 = random_int(0, $height);
            $x2 = random_int(0, $width);
            $y2 = random_int(0, $height);
            $opacity = random_int(20, 40) / 100;
            $color = $allowedLineColors[array_rand($allowedLineColors)];
            $lines .= '<line x1="' . $x1 . '" y1="' . $y1 . '" x2="' . $x2 . '" y2="' . $y2 . '" stroke="' . $color . '" stroke-opacity="' . $opacity . '" stroke-width="1"/>';
        }

        // Generate noise dots
        $dots = '';
        for ($i = 0; $i < 30; $i++) {
            $cx = random_int(5, $width - 5);
            $cy = random_int(5, $height - 5);
            $r = random_int(1, 2);
            $opacity = random_int(20, 45) / 100;
            $color = $allowedDotColors[array_rand($allowedDotColors)];
            $dots .= '<circle cx="' . $cx . '" cy="' . $cy . '" r="' . $r . '" fill="' . $color . '" fill-opacity="' . $opacity . '"/>';
        }

        // Render each character with rotation and offset
        $chars = str_split($code);
        $charSpacing = $width / (count($chars) + 1);
        $charElements = '';
        $fontSize = 28;

        foreach ($chars as $i => $char) {
            // Only allow A-Z and 0-9 characters in SVG output
            if (! preg_match('/^[A-Z0-9]$/', $char)) {
                continue;
            }
            $x = $charSpacing * ($i + 1);
            $y = $height / 2 + random_int(-5, 5);
            $rotation = random_int(-15, 15);
            $color = $allowedTextColors[$i % count($allowedTextColors)];

            $charElements .= '<text x="' . $x . '" y="' . $y . '" '
                . 'font-family="\'Courier New\', monospace" '
                . 'font-size="' . $fontSize . '" '
                . 'font-weight="bold" '
                . 'fill="' . $color . '" '
                . 'text-anchor="middle" '
                . 'dominant-baseline="central" '
                . 'transform="rotate(' . $rotation . ' ' . $x . ' ' . $y . ')" '
                . 'letter-spacing="6">' . htmlspecialchars($char, ENT_QUOTES, 'UTF-8') . '</text>';
        }

        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $width . '" height="' . $height . '" viewBox="0 0 ' . $width . ' ' . $height . '">'
            . '<rect width="' . $width . '" height="' . $height . '" rx="4" ry="4" fill="' . $bg . '"/>'
            . $lines
            . $dots
            . $charElements
            . '</svg>';

        return $svg;
    }
}
