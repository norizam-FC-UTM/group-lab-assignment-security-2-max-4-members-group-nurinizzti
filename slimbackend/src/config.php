<?php
// ==========================================================
// INSECURE STARTER CONFIGURATION
// ==========================================================
// This file is intentionally simple for classroom use.
// Students should later discuss why secrets/configuration should
// not be hardcoded in real projects.

// Optional lightweight .env support (no extra package needed).
$envPath = dirname(__DIR__) . '/.env';
if (is_file($envPath) && is_readable($envPath)) {
    $envValues = parse_ini_file($envPath, false, INI_SCANNER_RAW);

    if (is_array($envValues)) {
        foreach ($envValues as $key => $value) {
            if (getenv($key) === false) {
                putenv($key . '=' . $value);
                $_ENV[$key] = $value;
            }
        }
    }
}

function envValue(string $key, string $default): string
{
    $value = getenv($key);
    return $value === false ? $default : (string) $value;
}

return [
    'db_host' => envValue('DB_HOST', '127.0.0.1'),
    'db_name' => envValue('DB_NAME', 'security_bmi_lab'),
    'db_user' => envValue('DB_USER', 'root'),
    'db_pass' => envValue('DB_PASS', ''),
    'db_charset' => envValue('DB_CHARSET', 'utf8mb4')
];
