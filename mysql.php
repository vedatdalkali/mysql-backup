<?php
/**
 * ==============================================================================
 * VEDO MYSQL BACKUP & ENTERPRISE SERVER MONITORING PANEL
 * ==============================================================================
 * PHP 8.0+ | MySQL 5.7+ / 8.0+ / MariaDB
 * Güvenlik, Veri Bütünlüğü, Tam Nesne Yedekleme, Güvenli Restore & Live Progress
 * ==============================================================================
 */

declare(strict_types=1);

if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    if (php_sapi_name() === 'cli') {
        fwrite(STDERR, "ERROR: Minimum PHP 8.0.0 gereklidir. Mevcut: " . PHP_VERSION . "\n");
        exit(1);
    }
    http_response_code(500);
    echo "Bu sistem minimum PHP 8.0.0 sürümünü gerektirmektedir. Mevcut sürüm: " . PHP_VERSION;
    exit;
}

$required_extensions = ['pdo', 'pdo_mysql', 'json', 'zlib', 'session', 'hash', 'mbstring'];
foreach ($required_extensions as $ext) {
    if (!extension_loaded($ext)) {
        if (php_sapi_name() === 'cli') {
            fwrite(STDERR, "ERROR: PHP uzantısı eksik: {$ext}\n");
            exit(1);
        }
        die("PHP uzantısı eksik: {$ext}");
    }
}

// Global Sabit Tanımlamaları
define('VEDO_BACKUP_FORMAT', '2');
define('VEDO_RESTORE_CHUNK_BYTES', 1048576); // 1 MB
define('VEDO_QUERY_BUFFER_MAX', 52428800); // 50 MB
define('VEDO_CHUNK_ROW_LARGE', 5000);
define('VEDO_CHUNK_ROW_MEDIUM', 2500);
define('VEDO_CHUNK_ROW_SMALL', 1500);
define('VEDO_CHUNK_ROW_DEFAULT', 800);
define('VEDO_MAX_LOG_SIZE', 5242880); // 5 MB
define('VEDO_DATABASE_OPERATION_LOCK', 'database_operation'); // Backup ve restore için ortak kilit
// Bu sabitler backup/restore akışlarında doğrudan kullanılır; gereksiz sabit bırakılmamıştır.

/**
 * Çıktı arabelleklemesini temizler.
 */


function clear_buffers(): void {
    if (headers_sent()) return;
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
}

clear_buffers();
if (!headers_sent() && ob_get_level() === 0) {
    ob_start();
}
if (php_sapi_name() !== 'cli') {
    @ini_set('display_errors', '0');
    @ini_set('display_startup_errors', '0');
}

/**
 * Güvenli dosya yazma kontrolü.
 */
function safe_file_put_contents(string $filepath, string $data, int $flags = 0): bool {
    $attempts = 0;
    $max_attempts = 3;
    $written = false;

    while ($attempts < $max_attempts) {
        $attempts++;
        $res = @file_put_contents($filepath, $data, $flags);
        if ($res !== false) {
            $written = true;
            break;
        }
        usleep(50000);
    }

    if (!$written) {
        $lastError = error_get_last();
        $errMsg = $lastError['message'] ?? 'Bilinmeyen Disk I/O Hatası';
        if (class_exists('Logger')) {
            Logger::error("Dosya yazma başarısız [{$filepath}] ({$attempts} deneme): {$errMsg}");
        }
        return false;
    }
    return true;
}

class Logger {
    private static string $logFile = '';
    private static string $logDir = '';
    private static bool $available = false;
    private static int $maxRotateFiles = 5;
    public static function init(string $dir, int $rotateCount = 5): void {
        self::$logDir = $dir;
        self::$logFile = $dir . '/system.log';
        self::$available = is_dir($dir) && is_writable($dir);
        self::$maxRotateFiles = max(1, $rotateCount);
    }
    public static function log(string $level, string $message): void {
        if (empty(self::$logFile)) return;

        $message = preg_replace('/(password|pass|token|secret|csrf|session_id)=["\']?[^"\'&\s]+["\']?/i', '$1=***REDACTED***', $message);

        if (self::$available && is_file(self::$logFile) && filesize(self::$logFile) > VEDO_MAX_LOG_SIZE) {
            $rotLockFile = self::$logDir . '/rotation.lock';
            $rotFp = @fopen($rotLockFile, 'c+');

            if ($rotFp && flock($rotFp, LOCK_EX)) {
                if (is_file(self::$logFile) && filesize(self::$logFile) > VEDO_MAX_LOG_SIZE) {
                    for ($i = self::$maxRotateFiles - 1; $i >= 1; $i--) {
                        $old = self::$logDir . "/system.log.$i";
                        $new = self::$logDir . "/system.log." . ($i + 1);
                        if (is_file($old)) @rename($old, $new);
                    }
                    @rename(self::$logFile, self::$logDir . "/system.log.1");
                }
                fflush($rotFp);
                flock($rotFp, LOCK_UN);
            }
            if (is_resource($rotFp)) fclose($rotFp);
        }

        $date = date('Y-m-d H:i:s');
        $pid = getmypid() ?: 0;
        $line = sprintf("[%s] [%s][PID %d] %s\n", $date, strtoupper($level), $pid, $message);

        if (self::$available) {
            if (!safe_file_put_contents(self::$logFile, $line, FILE_APPEND | LOCK_EX)) {
                error_log("VEDO_LOGGER_FALLBACK: " . trim($line));
            }
        } else {
            error_log("VEDO_LOGGER_FALLBACK: " . trim($line));
        }
    }
    public static function error(string $msg): void { self::log('ERROR', $msg); }
    public static function warning(string $msg): void { self::log('WARNING', $msg); }
    public static function info(string $msg): void { self::log('INFO', $msg); }
}

$nonce = base64_encode(random_bytes(16));

if (php_sapi_name() !== 'cli') {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: no-referrer");
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Pragma: no-cache");
    header("Expires: 0");
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';");

    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
    }

    header("Permissions-Policy: camera=(), microphone=(), geolocation=(), autoplay=(), fullscreen=(), payment=(), usb=(), serial=(), accelerometer=()");
    header("Cross-Origin-Opener-Policy: same-origin");
    header("Cross-Origin-Resource-Policy: same-origin");
}

$default_pass = 'siteye_giriş_şifreniz';

$config = [
    // MySQL sunucusunun adresini belirtir. Ortam değişkeni tanımlıysa onu kullanır.
    'db_host'            => getenv('VEDO_DB_HOST') ?: 'localhost',
    // MySQL bağlantısında kullanılacak veritabanı kullanıcı adını belirtir.
    'db_user'            => getenv('VEDO_DB_USER') ?: 'mysql_kullanıcı_adınız',
    // MySQL bağlantısında kullanılacak veritabanı şifresini belirtir.
    'db_pass'            => getenv('VEDO_DB_PASSWORD') ?: 'mysql_şifreniz',
    // Yedeklenecek ve restore işlemlerinde kullanılacak veritabanının adını belirtir.
    'db_name'            => getenv('VEDO_DB_NAME') ?: 'mysql_db_adı',
    // Panel yönetici girişinde kullanılacak kullanıcı adını belirtir.
    'auth_user'          => getenv('VEDO_ADMIN_USER') ?: 'siteye_giriş_kullanıcı_adınız',
    // Panel yönetici girişinde kullanılacak şifreyi belirtir.
    'auth_pass'          => getenv('VEDO_ADMIN_PASSWORD') ?: $default_pass,
    // Yedek klasöründe en fazla kaç adet SQL yedeği tutulacağını belirtir.
    'max_backups'        => 30,
    // Otomatik cron yedekleme isteklerini doğrulamak için kullanılan güvenlik anahtarını belirtir.
    'cron_token'         => getenv('VEDO_CRON_TOKEN') ?: 'sql_backup_' . substr(md5('sql_backup_salt'), 0, 10),
    // Backup sırasında tek bir INSERT komutuna en fazla kaç satır yazılacağını belirler.
    'max_insert_rows'    => 500,
    // PDO bağlantısının kalıcı olarak açık tutulup tutulmayacağını belirler.
    'use_persistent_pdo' => false,
    // Aynı kullanıcı için izin verilen başarısız giriş denemesi sayısını belirler.
    'max_login_attempts' => 5,
    // Aynı IP adresinden izin verilen başarısız giriş denemesi sayısını belirler.
    'max_ip_attempts'    => 20,
    // Aynı kullanıcı hesabı için izin verilen başarısız deneme sayısını belirler.
    'max_user_attempts'  => 10,
    // Başarısız giriş denemelerinin sayıldığı zaman aralığını saniye olarak belirler.
    'rate_limit_window'  => 900,
    // Güvenlik nedeniyle kilitlenen hesabın ne kadar süre kilitli kalacağını saniye olarak belirler.
    'lockout_time'       => 900,
    // Backup veya restore sırasında kullanılan ortak işlem kilidinin zaman aşımını saniye olarak belirler.
    'lock_timeout'       => 60,
    // Güncel log dosyası büyüdüğünde kaç eski log dosyasının saklanacağını belirler.
    'log_rotate_count'   => 5,
    // Panelin genel yazı tipini belirler.
    'ui_font' => 'Tahoma, Arial, sans-serif',
    // Kullanıcının kayıtlı bir tema tercihi yoksa açılacak varsayılan temayı belirler: 'dark' veya 'light'.
    'ui_default_theme' => 'light',
    // Restore tamamlandıktan sonra veritabanı bütünlük kontrolünün yapılıp yapılmayacağını belirler.
    'verify_after_restore' => true,
    // Restore tamamlandıktan sonra tablolar için ANALYZE TABLE işleminin yapılıp yapılmayacağını belirler.
    'analyze_after_restore' => false
];

$backup_dir = __DIR__ . '/mysqlyedek';

if (!is_dir($backup_dir)) {
    if (!mkdir($backup_dir, 0755, true) && !is_dir($backup_dir)) {
        if (php_sapi_name() === 'cli') {
            fwrite(STDERR, "ERROR: Yedekleme klasoru olusturulamadi: {$backup_dir}\n");
            exit(1);
        }
        http_response_code(500);
        die("Kritik Hata: Yedekleme klasörü (" . htmlspecialchars($backup_dir) . ") oluşturulamadı!");
    }
}

Logger::init($backup_dir, (int)$config['log_rotate_count']);

/**
 * Merkezi beklenmeyen hata yakalama.
 * Mevcut iş akışlarını değiştirmez; yalnızca kullanıcıya ham PHP hatası sızmasını önler.
 */
set_exception_handler(static function (Throwable $e): void {
    Logger::error('Yakalanmamış istisna: ' . get_class($e) . ' - ' . $e->getMessage());

    if (headers_sent()) {
        return;
    }

    $isJson = str_contains(strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? '')), 'application/json')
        || isset($_GET['action']);

    if ($isJson) {
        json_response(false, 'Beklenmeyen bir sunucu hatası oluştu. Logları kontrol edin.', [], 500);
    }

    http_response_code(500);
    echo 'Beklenmeyen bir sunucu hatası oluştu. Lütfen sistem loglarını kontrol edin.';
    exit;
});

register_shutdown_function(static function (): void {
    $error = error_get_last();
    if (!$error || !in_array($error['type'], [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE], true)) {
        return;
    }

    Logger::error(sprintf(
        'Kritik PHP hatası: %s | %s:%d',
        (string)($error['message'] ?? 'Bilinmeyen hata'),
        (string)($error['file'] ?? '-'),
        (int)($error['line'] ?? 0)
    ));

    if (!headers_sent()) {
        http_response_code(500);
    }
});

$htaccess_path = $backup_dir . '/.htaccess';
if (!file_exists($htaccess_path)) {
    safe_file_put_contents($htaccess_path, "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>");
}

$index_path = $backup_dir . '/index.html';
if (!file_exists($index_path)) {
    safe_file_put_contents($index_path, '');
}

if (!is_writable($backup_dir)) {
    if (php_sapi_name() === 'cli') {
        fwrite(STDERR, "ERROR: Yedek klasoru yazilabilir degil.\n");
        exit(1);
    }
    die("Yedek klasörü yazılabilir değil.");
}

class SchemaCache {
    private static array $cache = [];
    private static int $maxItems = 1000;
    public static function get(string $key) {
        if (array_key_exists($key, self::$cache)) {
            $value = self::$cache[$key];
            unset(self::$cache[$key]);
            self::$cache[$key] = $value;
            return $value;
        }
        return null;
    }
    public static function set(string $key, $value): void {
        if (array_key_exists($key, self::$cache)) {
            unset(self::$cache[$key]);
        } elseif (count(self::$cache) >= self::$maxItems) {
            reset(self::$cache);
            $oldestKey = key(self::$cache);
            if ($oldestKey !== null) {
                unset(self::$cache[$oldestKey]);
            }
        }
        self::$cache[$key] = $value;
    }
    public static function clear(): void {
        self::$cache = [];
    }
}

function validate_backup_filename(string $filename): bool {
    if ($filename === '' || strlen($filename) > 255) {
        return false;
    }
    if (str_contains($filename, "\0") || str_contains($filename, '/') || str_contains($filename, '\\')) {
        return false;
    }
    return (bool)preg_match('/^[A-Za-z0-9._-]+\.sql\.gz$/', $filename);
}
function validate_path_safe(string $filePath, string $baseDir): string {
    $realBase = realpath($baseDir);
    if (!$realBase) {
        throw new Exception("Geçersiz ana dizin yolu!");
    }

    $realPath = realpath($filePath);
    if ($realPath !== false) {
        if (!str_starts_with($realPath, $realBase . DIRECTORY_SEPARATOR) && $realPath !== $realBase) {
            throw new Exception("Güvenlik İhlali: Yetkisiz dizin erişimi engellendi!");
        }
        return $realPath;
    }

    $dirName = dirname($filePath);
    $fileName = basename($filePath);
    $realDir = realpath($dirName);

    if (!$realDir || (!str_starts_with($realDir, $realBase . DIRECTORY_SEPARATOR) && $realDir !== $realBase)) {
        throw new Exception("Güvenlik İhlali: Yetkisiz hedef dizin erişimi!");
    }

    if (preg_match('/\.\.[\/\\\\]/', $fileName) || str_contains($fileName, "\0")) {
        throw new Exception("Güvenlik İhlali: Geçersiz dosya adı formatı!");
    }

    return $realDir . DIRECTORY_SEPARATOR . $fileName;
}
function require_post(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        json_response(false, 'Bu işlem için POST isteği gereklidir.', [], 405);
    }
}
function verify_csrf_token(string $token): bool {
    if ($token === '') {
        return false;
    }

    if (session_status() === PHP_SESSION_ACTIVE) {
        $expected = (string)($_SESSION['csrf_token'] ?? '');
        if ($expected !== '' && hash_equals($expected, $token)) {
            return true;
        }
    }

    foreach ([
        $GLOBALS['csrf_token'] ?? null,
        $GLOBALS['config']['csrf_token'] ?? null,
        $_SERVER['VEDO_CSRF_TOKEN'] ?? null
    ] as $expected) {
        if (is_string($expected) && $expected !== '' && hash_equals($expected, $token)) {
            return true;
        }
    }

    foreach (['check_csrf_token', 'csrf_validate', 'validate_csrf_token'] as $helper) {
        if (function_exists($helper)) {
            try {
                return (bool)$helper($token);
            } catch (Throwable $e) {
                return false;
            }
        }
    }

    return false;
}
/**
 * Büyük log dosyalarından yalnızca son kayıtları RAM'e alır.
 */
function read_last_file_lines(string $filePath, int $maxLines = 200, int $chunkBytes = 65536): array {
    if ($maxLines < 1 || $chunkBytes < 1024 || !is_file($filePath) || !is_readable($filePath)) {
        return [];
    }

    $handle = @fopen($filePath, 'rb');
    if ($handle === false) {
        return [];
    }

    try {
        if (@fseek($handle, 0, SEEK_END) !== 0) {
            return [];
        }

        $position = ftell($handle);
        if ($position === false || $position === 0) {
            return [];
        }

        $buffer = '';
        $lines = [];

        while ($position > 0 && count($lines) <= $maxLines) {
            $readLength = min($chunkBytes, $position);
            $position -= $readLength;
            if (@fseek($handle, $position, SEEK_SET) !== 0) {
                return [];
            }

            $chunk = fread($handle, $readLength);
            if ($chunk === false) {
                return [];
            }

            $buffer = $chunk . $buffer;
            $parts = preg_split('/\R/', $buffer);
            if ($parts === false) {
                return [];
            }

            $buffer = array_shift($parts) ?? '';
            while (count($parts) > 0) {
                $line = array_pop($parts);
                if ($line !== null && $line !== '') {
                    array_unshift($lines, $line);
                    if (count($lines) >= $maxLines) {
                        break 2;
                    }
                }
            }
        }

        if ($buffer !== '' && count($lines) < $maxLines) {
            array_unshift($lines, $buffer);
        }

        return array_slice($lines, -$maxLines);
    } finally {
        fclose($handle);
    }
}

function json_response(bool $success, string $message = '', array $data = [], int $httpCode = 200): void {
    clear_buffers();
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    $json = json_encode([
        'success' => $success,
        'message' => $message,
        'data'    => $data
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

    if ($json === false) {
        $json = '{"success":false,"message":"JSON yanıtı oluşturulamadı.","data":[]}';
        http_response_code(500);
    }

    echo $json;
    exit;
}
function get_dynamic_system_load(): int {
    static $core_count = null;
    if (function_exists('sys_getloadavg')) {
        $loads = sys_getloadavg();
        if (is_array($loads) && isset($loads[0])) {
            if ($core_count === null) {
                $core_count = 1;
                if (is_readable('/proc/cpuinfo')) {
                    $cpu_info = file_get_contents('/proc/cpuinfo');
                    if ($cpu_info !== false) {
                        $core_count = max(1, substr_count($cpu_info, 'processor'));
                    }
                }
            }
            $cpu_pct = ($loads[0] / $core_count) * 100;
            if ($cpu_pct > 70) return 2;
            if ($cpu_pct > 30) return 5;
        }
    }
    return 7;
}
function calculate_adaptive_chunk_size(PDO $pdo, string $db_name, string $table): int {
    if (!preg_match('/^[A-Za-z0-9_$]+$/', $table)) return VEDO_CHUNK_ROW_DEFAULT;

    $base_chunk = VEDO_CHUNK_ROW_DEFAULT;
    try {
        $stmt = $pdo->prepare("SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?");
        $stmt->execute([$db_name, $table]);
        $rows = (int)($stmt->fetchColumn() ?? 0);
        $stmt->closeCursor();

        if ($rows > 500000)      $base_chunk = VEDO_CHUNK_ROW_LARGE;
        elseif ($rows > 100000) $base_chunk = VEDO_CHUNK_ROW_MEDIUM;
        elseif ($rows > 10000)  $base_chunk = VEDO_CHUNK_ROW_SMALL;
    } catch (Exception $e) {
        $base_chunk = VEDO_CHUNK_ROW_DEFAULT;
    }

    $sys_load_level = get_dynamic_system_load();
    if ($sys_load_level <= 3) {
        $base_chunk = (int)($base_chunk * 0.5);
    }

    $avail_ram = get_available_server_memory_bytes();
    if ($avail_ram < 256 * 1024 * 1024) {
        return (int)min($base_chunk, 500);
    } elseif ($avail_ram < 512 * 1024 * 1024) {
        return (int)min($base_chunk, 1000);
    }

    return max(200, $base_chunk);
}
function acquire_system_lock(string $backup_dir, string $type = 'general', int $timeout = 60): mixed {
    $lock_file = $backup_dir . '/' . $type . '.lock';
    $fp = fopen($lock_file, 'c+');
    if (!$fp) return false;

    $current_host = gethostname() ?: 'host';
    $current_pid = getmypid() ?: 0;
    $now = time();

    if (!flock($fp, LOCK_EX | LOCK_NB)) {
        $content = '';
        rewind($fp);
        while (($line = fgets($fp)) !== false) {
            $content .= $line;
        }
        $data = json_decode($content, true);
        $lock_active = false;

        if (is_array($data)) {
            $pid = (int)($data['pid'] ?? 0);
            $host = (string)($data['host'] ?? '');
            $last_hb = (int)($data['last_heartbeat'] ?? $data['time'] ?? $now);
            $process_exists = false;

            if ($pid > 0 && ($host === '' || $host === $current_host)) {
                if (function_exists('posix_kill')) {
                    $process_exists = posix_kill($pid, 0);
                } elseif (PHP_OS_FAMILY === 'Linux' && is_dir('/proc/' . $pid)) {
                    $process_exists = true;
                } elseif (PHP_OS_FAMILY === 'Windows') {
                    $process_exists = false;
                    if (function_exists('exec')) {
                        $win_check = [];
                        @exec("powershell -NoProfile -Command \"Get-Process -Id {$pid} -ErrorAction SilentlyContinue\"", $win_check);
                        $process_exists = !empty($win_check);
                    }
                }
            }

            $lock_active = $process_exists ? (($now - $last_hb) <= $timeout) : false;
        } else {
            $stat = fstat($fp);
            $mtime = $stat['mtime'] ?? $now;
            $lock_active = ($now - $mtime) <= $timeout;
        }

        if ($lock_active) {
            fclose($fp);
            return false;
        } else {
            if (!flock($fp, LOCK_EX)) {
                fclose($fp);
                return false;
            }
        }
    }

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode([
        'time'           => $now,
        'started_at'     => $now,
        'last_heartbeat' => $now,
        'pid'            => $current_pid,
        'host'           => $current_host
    ]));
    fflush($fp);

    return $fp;
}
function update_system_lock_heartbeat(mixed $lock_fp): void {
    static $last_update_time = 0;
    $now = time();

    if (($now - $last_update_time) < 5 && $last_update_time !== 0) {
        return;
    }

    if (is_resource($lock_fp)) {
        rewind($lock_fp);
        $content = '';
        while (($line = fgets($lock_fp)) !== false) {
            $content .= $line;
        }
        $data = json_decode($content, true);
        if (!is_array($data)) {
            $data = [
                'started_at' => $now,
                'pid'        => getmypid() ?: 0,
                'host'       => gethostname() ?: 'host'
            ];
        }
        $data['last_heartbeat'] = $now;
        $data['time'] = $now;

        ftruncate($lock_fp, 0);
        rewind($lock_fp);
        fwrite($lock_fp, json_encode($data));
        fflush($lock_fp);
        $last_update_time = $now;
    }
}
function release_system_lock(mixed $lock_fp): void {
    if (is_resource($lock_fp)) {
        flock($lock_fp, LOCK_UN);
        fclose($lock_fp);
    }
}
function with_database_operation_lock(string $backup_dir, int $timeout, callable $callback): mixed {
    $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $timeout);
    if (!$lock_handle) {
        throw new Exception('Başka bir veritabanı işlemi aktif. Yeni işlem başlatılamaz.');
    }
    try {
        require_database_operation_lock($lock_handle, $backup_dir);
        update_system_lock_heartbeat($lock_handle);
        return $callback();
    } finally {
        release_system_lock($lock_handle);
    }
}
function require_database_operation_lock(mixed $lock_handle, string $backup_dir): void {
    if (!is_resource($lock_handle)) {
        throw new Exception('Veritabanı işlemi ortak kilit olmadan çalıştırılamaz.');
    }
    $lockPath = $backup_dir . '/' . VEDO_DATABASE_OPERATION_LOCK . '.lock';
    $meta = stream_get_meta_data($lock_handle);
    $uri = (string)($meta['uri'] ?? '');
    if ($uri !== '' && realpath($uri) !== realpath($lockPath)) {
        throw new Exception('Geçersiz veritabanı işlem kilidi kullanıldı.');
    }
}
function safe_transaction_rollback(?PDO $pdo): void {
    if ($pdo instanceof PDO && $pdo->inTransaction()) {
        try {
            $pdo->rollBack();
        } catch (Exception $e) {
            Logger::error("Rollback hatası: " . $e->getMessage());
        }
    }
}
function limit_backup_files(string $dir, int $max): void {
    $real_backup_dir = realpath($dir);
    if (!$real_backup_dir) return;

    $sql_files = [];

    try {
        $iterator = new DirectoryIterator($real_backup_dir);
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isDot() || !$fileinfo->isFile()) continue;

            $filename = $fileinfo->getFilename();

            if (str_ends_with($filename, '.sql.gz')) {
                $sql_files[] = [
                    'path' => $fileinfo->getPathname(),
                    'mtime' => $fileinfo->getMTime()
                ];
            }
        }
    } catch (Exception $e) {
        Logger::error("DirectoryIterator hatası: " . $e->getMessage());
        return;
    }

    if (count($sql_files) > $max) {
        usort($sql_files, fn($a, $b) => $a['mtime'] <=> $b['mtime']);
        $delete_count = count($sql_files) - $max;

        for ($i = 0; $i < $delete_count; $i++) {
            $target = $sql_files[$i]['path'];
            try {
                $real_file = validate_path_safe($target, $real_backup_dir);
                unlink($real_file);

                $sha_file = $target . '.sha256';
                if (is_file($sha_file)) {
                    @unlink(validate_path_safe($sha_file, $real_backup_dir));
                }
                $meta_file = $target . '.meta.json';
                if (is_file($meta_file)) {
                    @unlink(validate_path_safe($meta_file, $real_backup_dir));
                }

            } catch (Exception $e) {
                Logger::warning("Eski yedek silinirken hata oluştu: " . $e->getMessage());
            }
        }
    }
}
function escape_string_safe(mixed $v, ?PDO $pdo = null): string {
    if ($v === null) return "NULL";
    if (is_bool($v)) return $v ? "1" : "0";
    if (is_int($v) || is_float($v)) return (string)$v;

    if (is_resource($v)) {
        $hex = '0x';
        while (!feof($v)) {
            $chunk = fread($v, 8192);
            if ($chunk !== false) {
                $hex .= bin2hex($chunk);
            }
        }
        return $hex === '0x' ? "''" : $hex;
    }

    if (is_string($v)) {
        if (!mb_check_encoding($v, 'UTF-8') || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $v)) {
            return "0x" . bin2hex($v);
        }
    }

    if ($pdo instanceof PDO) {
        $quoted = $pdo->quote((string)$v);
        if ($quoted !== false) {
            return $quoted;
        }
    }

    throw new Exception("PDO::quote() başarısız oldu, bağlantı hatası veya geçersiz karakter.");
}
function get_pdo(string $h, string $u, string $p, string $d, bool $force_reconnect = false, bool $use_persistent = false): PDO {
    static $instances = [];
    static $last_pings = [];

    if (count($instances) > 10) {
        $instances = array_slice($instances, -5, null, true);
        $last_pings = array_slice($last_pings, -5, null, true);
    }

    $key = "{$h}|{$d}|{$u}|" . ($use_persistent ? '1' : '0');
    $now = microtime(true);

    if (isset($instances[$key]) && !$force_reconnect) {
        $last_ping = $last_pings[$key] ?? 0.0;
        if (($now - $last_ping) > 30.0) {
            try {
                $pingStmt = $instances[$key]->query("SELECT 1");
                if ($pingStmt) {
                    $pingStmt->fetchColumn();
                    $pingStmt->closeCursor();
                }
                $last_pings[$key] = $now;
                return $instances[$key];
            } catch (PDOException $e) {
                $instances[$key] = null;
                unset($instances[$key]);
            }
        } else {
            return $instances[$key];
        }
    }

    $dsn = "mysql:host={$h};dbname={$d};charset=utf8mb4";
    $options = [
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true,
        PDO::ATTR_ERRMODE                  => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE       => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT                  => 60,
        PDO::ATTR_EMULATE_PREPARES         => false,
        PDO::ATTR_PERSISTENT               => (bool)$use_persistent
    ];

    $pdo = new PDO($dsn, $u, $p, $options);
    $pdo->exec("SET SESSION sql_mode = REPLACE(@@sql_mode, 'NO_BACKSLASH_ESCAPES', '')");
    $instances[$key] = $pdo;
    $last_pings[$key] = microtime(true);

    return $instances[$key];
}
function get_database_size_bytes(PDO $pdo, string $db_name): int {
    try {
        $stmt = $pdo->prepare("SELECT SUM(DATA_LENGTH + INDEX_LENGTH) as ts FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?");
        $stmt->execute([$db_name]);
        $res = $stmt->fetch();
        $stmt->closeCursor();
        return (int)($res['ts'] ?? 0);
    } catch (Exception $e) {
        return 0;
    }
}
function check_sufficient_disk_space(PDO $pdo, string $db_name, string $dir): void {
    $free_space = @disk_free_space($dir);

    if ($free_space === false) {
        Logger::warning("disk_free_space() okunamadı. Disk kontrolü atlandı.");
        return;
    }

    $db_size = get_database_size_bytes($pdo, $db_name);
    $estimated_needed = max(50 * 1024 * 1024, (int)($db_size * 0.50));

    if ($free_space < $estimated_needed) {
        throw new Exception(
            "Yetersiz disk alanı.\n" .
            "Boş Alan : " . format_bytes($free_space) . "\n" .
            "Gerekli  : " . format_bytes($estimated_needed)
        );
    }
}
function get_available_server_memory_bytes(): int {
    $available_bytes = 0;
    if (is_readable('/proc/meminfo')) {
        $meminfo = file_get_contents('/proc/meminfo');
        if ($meminfo !== false) {
            if (preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $meminfo, $matches)) {
                $available_bytes = (int)$matches[1] * 1024;
            } elseif (preg_match('/MemFree:\s+(\d+)\s+kB/i', $meminfo, $matches_free)) {
                $free = (int)$matches_free[1] * 1024;
                $buffers = preg_match('/Buffers:\s+(\d+)\s+kB/i', $meminfo, $m_buf) ? (int)$m_buf[1] * 1024 : 0;
                $cached = preg_match('/Cached:\s+(\d+)\s+kB/i', $meminfo, $m_cac) ? (int)$m_cac[1] * 1024 : 0;
                $available_bytes = $free + $buffers + $cached;
            }
        }
    } elseif (PHP_OS_FAMILY === 'Windows') {
        if (function_exists('exec')) {
            $ps_out = [];
            $exit_code = 1;
            @exec('powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory"', $ps_out, $exit_code);
            if ($exit_code === 0 && !empty($ps_out) && is_numeric(trim($ps_out[0] ?? ''))) {
                $available_bytes = (int)trim($ps_out[0]) * 1024;
            }
        }
    }

    if ($available_bytes <= 0) {
        $memory_limit_ini = ini_get('memory_limit');
        if ($memory_limit_ini && $memory_limit_ini !== '-1') {
            $val = (int)$memory_limit_ini;
            $unit = strtoupper(substr(trim($memory_limit_ini), -1));
            $available_bytes = match($unit) {
                'G' => $val * 1024 * 1024 * 1024,
                'M' => $val * 1024 * 1024,
                'K' => $val * 1024,
                default => $val
            };
        } else {
            $available_bytes = 512 * 1024 * 1024;
        }
    }

    return $available_bytes;
}
function calculate_dynamic_memory_limit(PDO $pdo, string $db_name): string {
    $min_limit_bytes = 512 * 1024 * 1024;
    $max_cap_bytes   = 8192 * 1024 * 1024;
    $db_size_bytes   = get_database_size_bytes($pdo, $db_name);

    $available_server_bytes = get_available_server_memory_bytes();
    $safe_server_limit = (int)($available_server_bytes * 0.90);

    $target_bytes = min($max_cap_bytes, max($min_limit_bytes, $db_size_bytes));
    $final_bytes  = min($safe_server_limit, $target_bytes);

    $current_ini = ini_get('memory_limit');
    if (!empty($current_ini) && $current_ini !== '-1') {
        $val = (int)$current_ini;
        $unit = strtoupper(substr(trim($current_ini), -1));
        $current_bytes = match($unit) {
            'G' => $val * 1024 * 1024 * 1024,
            'M' => $val * 1024 * 1024,
            'K' => $val * 1024,
            default => $val
        };
        if ($current_bytes > $final_bytes) {
            return $current_ini;
        }
    }

    $limit_str = ceil($final_bytes / (1024 * 1024)) . 'M';
    if (@ini_set('memory_limit', $limit_str) === false) {
        Logger::warning("memory_limit dinamik olarak '{$limit_str}' yapılandırılamadı.");
    }
    return $limit_str;
}
function init_pdo_with_dynamic_memory(array &$config): PDO {
    static $initialized = false;
    $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);

    if (!$initialized) {
        calculate_dynamic_memory_limit($pdo, $config['db_name']);
        $initialized = true;
    }
    return $pdo;
}
function get_table_columns(?PDO $pdo, string $db_name, string $table): string {
    $cache_key = "cols.{$db_name}.{$table}";
    $cached = SchemaCache::get($cache_key);
    if ($cached !== null) return $cached;
    if ($pdo === null) throw new Exception("Şema okunamıyor: PDO bağlantısı yok.");

    try {
        $stmt = $pdo->prepare("
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION ASC
        ");
        $stmt->execute([$db_name, $table]);
        $cols = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $stmt->closeCursor();

        if (!empty($cols)) {
            $formatted = implode(', ', array_map(fn($c) => "`" . str_replace("`", "``", $c) . "`", $cols));
            SchemaCache::set($cache_key, $formatted);
            return $formatted;
        }
    } catch (Exception $e) {
        Logger::error("get_table_columns hatası ($table): " . $e->getMessage());
    }

    throw new Exception("Tablo şeması okunamadı [{$table}]. Yedekleme durduruldu!");
}
function get_table_cursor_keys(?PDO $pdo, string $db_name, string $table): array {
    $cache_key = "keys.{$db_name}.{$table}";
    $cached = SchemaCache::get($cache_key);
    if ($cached !== null) return $cached;
    if ($pdo === null) return [];

    try {
        $stmt = $pdo->prepare("
            SELECT COLUMN_NAME
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'
            ORDER BY ORDINAL_POSITION ASC
        ");
        $stmt->execute([$db_name, $table]);
        $cols = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $stmt->closeCursor();

        if (!empty($cols)) {
            SchemaCache::set($cache_key, $cols);
            return $cols;
        }

        // PRIMARY KEY yoksa, tek bir NOT NULL UNIQUE index seçilir.
        // Farklı UNIQUE index'lerin kolonları birleştirilerek sahte bir bileşik
        // cursor oluşturulması bazı satırların atlanmasına veya tekrarlanmasına yol açabilir.
        $stmt = $pdo->prepare("
            SELECT s.INDEX_NAME, s.COLUMN_NAME, s.SEQ_IN_INDEX, c.IS_NULLABLE
            FROM information_schema.STATISTICS s
            JOIN information_schema.COLUMNS c
              ON s.TABLE_SCHEMA = c.TABLE_SCHEMA
             AND s.TABLE_NAME = c.TABLE_NAME
             AND s.COLUMN_NAME = c.COLUMN_NAME
            WHERE s.TABLE_SCHEMA = ?
              AND s.TABLE_NAME = ?
              AND s.NON_UNIQUE = 0
              AND s.INDEX_NAME <> 'PRIMARY'
            ORDER BY s.INDEX_NAME ASC, s.SEQ_IN_INDEX ASC
        ");
        $stmt->execute([$db_name, $table]);
        $unique_indexes = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $indexName = (string)($row['INDEX_NAME'] ?? '');
            if ($indexName === '') continue;
            $unique_indexes[$indexName][] = [
                'column' => (string)($row['COLUMN_NAME'] ?? ''),
                'nullable' => strtoupper((string)($row['IS_NULLABLE'] ?? 'YES')) !== 'NO',
                'sub_part' => $row['SUB_PART'] !== null ? (int)$row['SUB_PART'] : null,
                'seq' => (int)($row['SEQ_IN_INDEX'] ?? 0)
            ];
        }
        $stmt->closeCursor();

        foreach ($unique_indexes as $columns) {
            usort($columns, static fn(array $a, array $b): int => $a['seq'] <=> $b['seq']);
            if ($columns === [] || count(array_filter($columns, static fn(array $column): bool =>
                $column['nullable'] ||
                $column['column'] === '' ||
                $column['sub_part'] !== null
            )) > 0) {
                // Prefix UNIQUE index'ler tam kolon değerini temsil etmez; keyset
                // pagination için cursor olarak kullanılırsa satır atlama/tekrarlama
                // riski doğurabilir. Bu nedenle yalnızca tam kapsamlı index'leri kullan.
                continue;
            }
            $unique_cols = array_column($columns, 'column');
            SchemaCache::set($cache_key, $unique_cols);
            return $unique_cols;
        }

    } catch (Exception $e) {
        Logger::error("get_table_cursor_keys hatası ($table): " . $e->getMessage());
    }

    SchemaCache::set($cache_key, []);
    return [];
}
function get_table_auto_increment_key(?PDO $pdo, string $db_name, string $table): string {
    try {
        $stmt = $pdo->prepare("
            SELECT COLUMN_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND EXTRA LIKE '%auto_increment%'
            LIMIT 1
        ");
        $stmt->execute([$db_name, $table]);
        $col = $stmt->fetchColumn();
        $stmt->closeCursor();
        if ($col) {
            return (string)$col;
        }
    } catch (Exception $e) {
        Logger::error("get_table_auto_increment_key hatası ($table): " . $e->getMessage());
    }
    return '';
}
function format_bytes(int|float $bytes, int $precision = 2): string {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max((float)$bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min((int)$pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}
function safe_gzwrite(mixed $stream, string $data, bool $flush = false): void {
    $length = strlen($data);
    if ($length === 0) return;
    $written = gzwrite($stream, $data);
    if ($written === false || $written < $length) {
        throw new Exception("Gzip arşivine yazma başarısız oldu.");
    }
    if ($flush) {
        gzflush($stream, ZLIB_SYNC_FLUSH);
    }
}

/**
 * VERİTABANI NESNELERİ DIŞA AKTARIMI (VIEW, TRIGGER, PROCEDURE, FUNCTION, EVENT)
 */
function export_database_objects_to_stream(PDO $pdo, string $db_name, mixed $stream): void {
    safe_gzwrite($stream, "\n-- ==========================================\n-- DATABASE OBJECTS (VIEWS, PROCEDURES, FUNCTIONS, TRIGGERS, EVENTS)\n-- ==========================================\n\n");

    $exported = [
        'views' => 0,
        'procedures' => 0,
        'functions' => 0,
        'triggers' => 0,
        'events' => 0,
    ];

    // Eksik bir veritabanı nesnesi backup'ın başarılı sayılmasını engeller.

    // 1. VIEWS
    $stmt = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'VIEW'");
    $stmt->execute([$db_name]);
    $views = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    foreach ($views as $view) {
        $view = (string)$view;
        if ($view === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $view)) {
            throw new Exception("Geçersiz VIEW adı dışa aktarılamadı: {$view}");
        }
        $q = '`' . str_replace('`', '``', $view) . '`';
        try {
            $vStmt = $pdo->query("SHOW CREATE VIEW {$q}");
            $row = $vStmt ? $vStmt->fetch(PDO::FETCH_ASSOC) : false;
            if ($vStmt) $vStmt->closeCursor();
            $createSql = is_array($row) ? (string)($row['Create View'] ?? '') : '';
            if ($createSql === '') {
                throw new Exception("SHOW CREATE VIEW sonucu boş.");
            }
            $createSql = preg_replace('/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)/i', '', $createSql);
            safe_gzwrite($stream, "DROP VIEW IF EXISTS {$q};\n" . $createSql . ";\n\n");
            $exported['views']++;
        } catch (Throwable $e) {
            throw new Exception("VIEW dışa aktarılamadı [{$view}]: " . $e->getMessage(), 0, $e);
        }
    }

    // 2. PROCEDURES
    $stmt = $pdo->prepare("SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'PROCEDURE'");
    $stmt->execute([$db_name]);
    $procs = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    foreach ($procs as $proc) {
        $proc = (string)$proc;
        if ($proc === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $proc)) {
            throw new Exception("Geçersiz PROCEDURE adı dışa aktarılamadı: {$proc}");
        }
        $q = '`' . str_replace('`', '``', $proc) . '`';
        try {
            $pStmt = $pdo->query("SHOW CREATE PROCEDURE {$q}");
            $row = $pStmt ? $pStmt->fetch(PDO::FETCH_ASSOC) : false;
            if ($pStmt) $pStmt->closeCursor();
            $createSql = is_array($row) ? (string)($row['Create Procedure'] ?? '') : '';
            if ($createSql === '') {
                throw new Exception("SHOW CREATE PROCEDURE sonucu boş.");
            }
            $createSql = preg_replace('/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)/i', '', $createSql);
            safe_gzwrite($stream, "DROP PROCEDURE IF EXISTS {$q};\nDELIMITER //\n" . $createSql . " //\nDELIMITER ;\n\n");
            $exported['procedures']++;
        } catch (Throwable $e) {
            throw new Exception("PROCEDURE dışa aktarılamadı [{$proc}]: " . $e->getMessage(), 0, $e);
        }
    }

    // 3. FUNCTIONS
    $stmt = $pdo->prepare("SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'FUNCTION'");
    $stmt->execute([$db_name]);
    $funcs = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    foreach ($funcs as $func) {
        $func = (string)$func;
        if ($func === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $func)) {
            throw new Exception("Geçersiz FUNCTION adı dışa aktarılamadı: {$func}");
        }
        $q = '`' . str_replace('`', '``', $func) . '`';
        try {
            $fStmt = $pdo->query("SHOW CREATE FUNCTION {$q}");
            $row = $fStmt ? $fStmt->fetch(PDO::FETCH_ASSOC) : false;
            if ($fStmt) $fStmt->closeCursor();
            $createSql = is_array($row) ? (string)($row['Create Function'] ?? '') : '';
            if ($createSql === '') {
                throw new Exception("SHOW CREATE FUNCTION sonucu boş.");
            }
            $createSql = preg_replace('/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)/i', '', $createSql);
            safe_gzwrite($stream, "DROP FUNCTION IF EXISTS {$q};\nDELIMITER //\n" . $createSql . " //\nDELIMITER ;\n\n");
            $exported['functions']++;
        } catch (Throwable $e) {
            throw new Exception("FUNCTION dışa aktarılamadı [{$func}]: " . $e->getMessage(), 0, $e);
        }
    }

    // 4. TRIGGERS
    $stmt = $pdo->prepare("SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ? ORDER BY TRIGGER_NAME");
    $stmt->execute([$db_name]);
    $triggers = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    foreach ($triggers as $trig) {
        $trig = (string)$trig;
        if ($trig === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $trig)) {
            throw new Exception("Geçersiz TRIGGER adı dışa aktarılamadı: {$trig}");
        }
        $q = '`' . str_replace('`', '``', $trig) . '`';
        try {
            $tStmt = $pdo->query("SHOW CREATE TRIGGER {$q}");
            $row = $tStmt ? $tStmt->fetch(PDO::FETCH_ASSOC) : false;
            if ($tStmt) $tStmt->closeCursor();
            $createSql = is_array($row) ? (string)($row['SQL Original Statement'] ?? $row['Create Trigger'] ?? '') : '';
            if ($createSql === '') {
                throw new Exception("SHOW CREATE TRIGGER sonucu boş.");
            }
            $createSql = preg_replace('/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)/i', '', $createSql);
            safe_gzwrite($stream, "DROP TRIGGER IF EXISTS {$q};\nDELIMITER //\n" . $createSql . " //\nDELIMITER ;\n\n");
            $exported['triggers']++;
        } catch (Throwable $e) {
            throw new Exception("TRIGGER dışa aktarılamadı [{$trig}]: " . $e->getMessage(), 0, $e);
        }
    }

    // 5. EVENTS
    $stmt = $pdo->prepare("SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ? ORDER BY EVENT_NAME");
    $stmt->execute([$db_name]);
    $events = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    foreach ($events as $ev) {
        $ev = (string)$ev;
        if ($ev === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $ev)) {
            throw new Exception("Geçersiz EVENT adı dışa aktarılamadı: {$ev}");
        }
        $q = '`' . str_replace('`', '``', $ev) . '`';
        try {
            $eStmt = $pdo->query("SHOW CREATE EVENT {$q}");
            $row = $eStmt ? $eStmt->fetch(PDO::FETCH_ASSOC) : false;
            if ($eStmt) $eStmt->closeCursor();
            $createSql = is_array($row) ? (string)($row['Create Event'] ?? '') : '';
            if ($createSql === '') {
                throw new Exception("SHOW CREATE EVENT sonucu boş.");
            }
            $createSql = preg_replace('/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)/i', '', $createSql);
            safe_gzwrite($stream, "DROP EVENT IF EXISTS {$q};\nDELIMITER //\n" . $createSql . " //\nDELIMITER ;\n\n");
            $exported['events']++;
        } catch (Throwable $e) {
            throw new Exception("EVENT dışa aktarılamadı [{$ev}]: " . $e->getMessage(), 0, $e);
        }
    }

    Logger::info(sprintf(
        'DATABASE OBJECTS EXPORT TAMAMLANDI | db=%s | views=%d | procedures=%d | functions=%d | triggers=%d | events=%d',
        $db_name,
        $exported['views'],
        $exported['procedures'],
        $exported['functions'],
        $exported['triggers'],
        $exported['events']
    ));
}

/**
 * TEK TABLO İÇİN YALNIZCA OKUMA AMAÇLI DIŞA AKTARIM
 */
function export_single_table_to_stream(PDO $pdo, string $table, mixed $stream, string $db_name, int &$processed_total_rows, ?callable $on_progress = null, int $max_insert_rows = 500): void {
    if (!preg_match('/^[A-Za-z0-9_$]+$/', $table)) {
        throw new Exception("Geçersiz tablo tanımı tespit edildi.");
    }

    $stmtInfo = $pdo->prepare("SHOW CREATE TABLE `{$table}`");
    $stmtInfo->execute();
    $createTableStmt = $stmtInfo->fetch();
    $stmtInfo->closeCursor();

    $createTableSql = $createTableStmt['Create Table'] ?? $createTableStmt['Create View'] ?? '';

    if (!empty($createTableSql)) {
        $pattern = '/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)|\s+(ROW_FORMAT|ALGORITHM|DEFAULT\s+ENCRYPTION|SECONDARY_ENGINE|ENGINE_ATTRIBUTE)\s*=\s*[\'"]?[^\s;]+[\'"]?|\s+TABLESPACE\s+`?[a-zA-Z0-9_]+`?(\s+STORAGE\s+[a-zA-Z0-9_]+)?/i';
        $createTableSql = preg_replace($pattern, '', $createTableSql);
        $createTableSql = str_ireplace('SQL SECURITY DEFINER', 'SQL SECURITY INVOKER', $createTableSql);
    }

    $schema_sql = "\nDROP TABLE IF EXISTS `{$table}`;\n" . $createTableSql . ";\n\n";
    $is_view = isset($createTableStmt['Create View']);

    safe_gzwrite($stream, $schema_sql);

    if ($is_view) return;

    $chunk_size = calculate_adaptive_chunk_size($pdo, $db_name, $table);
    $columns_select = get_table_columns($pdo, $db_name, $table);
    $cursor_keys = get_table_cursor_keys($pdo, $db_name, $table);

    if (empty($cursor_keys)) {
        $fallback_auto_key = get_table_auto_increment_key($pdo, $db_name, $table);
        if (!empty($fallback_auto_key)) {
            $cursor_keys = [$fallback_auto_key];
        }
    }

    $use_keyset = !empty($cursor_keys);
    $key_count = count($cursor_keys);
    $quoted_keys = array_map(fn($k) => "`$k`", $cursor_keys);
    $order_by_clause = $use_keyset ? implode(', ', $quoted_keys) : '';

    $last_values = null;
    $offset = 0;
    $total_exported_rows = 0;
    $write_counter = 0;

    $max_buffer_bytes = 2 * 1024 * 1024;

    while (true) {
        if ($use_keyset) {
            if ($last_values === null) {
                $stmt = $pdo->prepare("SELECT {$columns_select} FROM `{$table}` ORDER BY {$order_by_clause} LIMIT :limit");
            } else {
                if ($key_count === 1) {
                    $stmt = $pdo->prepare("SELECT {$columns_select} FROM `{$table}` WHERE {$quoted_keys[0]} > :last_val ORDER BY {$order_by_clause} LIMIT :limit");
                    $stmt->bindValue(':last_val', $last_values[0]);
                } else {
                    $where_clauses = [];
                    for ($i = 0; $i < $key_count; $i++) {
                        $clause = "(";
                        for ($j = 0; $j < $i; $j++) {
                            $clause .= "{$quoted_keys[$j]} = :eq_val_{$i}_{$j} AND ";
                        }
                        $clause .= "{$quoted_keys[$i]} > :gt_val_{$i})";
                        $where_clauses[] = $clause;
                    }
                    $where_sql = implode(" OR ", $where_clauses);

                    $stmt = $pdo->prepare("SELECT {$columns_select} FROM `{$table}` WHERE ({$where_sql}) ORDER BY {$order_by_clause} LIMIT :limit");
                    for ($i = 0; $i < $key_count; $i++) {
                        for ($j = 0; $j < $i; $j++) {
                            $stmt->bindValue(":eq_val_{$i}_{$j}", $last_values[$j]);
                        }
                        $stmt->bindValue(":gt_val_{$i}", $last_values[$i]);
                    }
                }
            }
        } else {
            $stmt = $pdo->prepare("SELECT {$columns_select} FROM `{$table}` LIMIT :offset, :limit");
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        }

        $stmt->bindValue(':limit', $chunk_size, PDO::PARAM_INT);
        $stmt->execute();

        $has_rows = false;
        $rows_buffer = [];
        $rows_buffer_bytes = 0;
        $last_row = null;

        while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
            $has_rows = true;
            $total_exported_rows++;
            $processed_total_rows++;

            $escaped_row = "(" . implode(',', array_map(fn($val) => escape_string_safe($val, $pdo), $r)) . ")";
            $row_len = strlen($escaped_row);

            $rows_buffer[] = $escaped_row;
            $rows_buffer_bytes += $row_len;
            $last_row = $r;

            if (count($rows_buffer) >= $max_insert_rows || $rows_buffer_bytes >= $max_buffer_bytes) {
                $write_counter++;
                $should_flush = ($write_counter % 10 === 0);
                safe_gzwrite($stream, "INSERT INTO `{$table}` VALUES\n" . implode(",\n", $rows_buffer) . ";\n", $should_flush);
                $rows_buffer = [];
                $rows_buffer_bytes = 0;
            }
        }

        if (!empty($rows_buffer)) {
            $write_counter++;
            $should_flush = ($write_counter % 10 === 0);
            safe_gzwrite($stream, "INSERT INTO `{$table}` VALUES\n" . implode(",\n", $rows_buffer) . ";\n", $should_flush);
            $rows_buffer = [];
            $rows_buffer_bytes = 0;
        }

        $stmt->closeCursor();

        if (is_callable($on_progress)) {
            call_user_func($on_progress);
        }

        if (!$has_rows) break;

        if ($use_keyset) {
            $last_values = [];
            foreach ($cursor_keys as $k) $last_values[] = $last_row[$k];
        } else {
            $offset += $chunk_size;
        }

        if ($total_exported_rows % 10000 === 0) gc_collect_cycles();
    }
}

/**
 * BACKUP ÖNCESİ MYISAM ONARIMI
 * Sadece MyISAM tablolarında REPAIR TABLE çalıştırır.
 * InnoDB ve diğer motorlara dokunmaz.
 */
function repair_myisam_tables_before_backup(PDO $pdo, string $db_name): void {
    $stmt = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND ENGINE = 'MyISAM' AND TABLE_TYPE = 'BASE TABLE'");
    $stmt->execute([$db_name]);
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    foreach ($tables as $table) {
        $table = (string)$table;
        if ($table === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $table)) {
            throw new Exception("MyISAM tablo adı doğrulanamadı: {$table}");
        }

        $quoted = '`' . str_replace('`', '``', $table) . '`';
        try {
            $repair = $pdo->query("REPAIR TABLE {$quoted}");
            $messages = $repair ? $repair->fetchAll(PDO::FETCH_ASSOC) : [];
            if ($repair) $repair->closeCursor();

            $errorMessages = [];
            foreach ($messages as $row) {
                $msgType = strtoupper((string)($row['Msg_type'] ?? ''));
                $msgText = (string)($row['Msg_text'] ?? '');
                if ($msgType === 'ERROR') {
                    $errorMessages[] = $msgText;
                }
            }

            if ($errorMessages) {
                throw new Exception("MyISAM REPAIR başarısız [{$table}]: " . implode(' | ', $errorMessages));
            }

            Logger::info("Backup öncesi MyISAM REPAIR tamamlandı: {$table}");
        } catch (Throwable $e) {
            Logger::error("MyISAM REPAIR hatası [{$table}]: " . $e->getMessage());
            throw $e;
        }
    }
}

/**
 * MYISAM YEDEKLEME OKUMA KİLİDİ
 * MyISAM tabloları ayrı bir PDO bağlantısında READ LOCK altında tutulur.
 * Böylece ana PDO üzerindeki InnoDB consistent snapshot transaction'ı ile
 * LOCK TABLES birbirine karışmaz.
 */
function acquire_myisam_read_locks(string $h, string $u, string $p, string $d): array {
    $lockPdo = get_pdo($h, $u, $p, $d, true, false);
    $stmt = $lockPdo->prepare("
        SELECT TABLE_NAME
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = ? AND ENGINE = 'MyISAM' AND TABLE_TYPE = 'BASE TABLE'
        ORDER BY TABLE_NAME
    ");
    $stmt->execute([$d]);
    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
    $stmt->closeCursor();

    if (!$tables) {
        return ['pdo' => null, 'tables' => []];
    }

    $quoted = [];
    foreach ($tables as $table) {
        $table = (string)$table;
        if ($table === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $table)) {
            throw new Exception("MyISAM tablo adı doğrulanamadı: {$table}");
        }
        $quoted[] = '`' . str_replace('`', '``', $table) . '`';
    }

    $lockPdo->exec("LOCK TABLES " . implode(", ", array_map(fn($t) => $t . " READ", $quoted)));
    Logger::info("MyISAM READ LOCK aktif: " . count($quoted) . " tablo.");
    return ['pdo' => $lockPdo, 'tables' => $quoted];
}
function release_myisam_read_locks(?PDO $lockPdo): void {
    if ($lockPdo instanceof PDO) {
        try {
            $lockPdo->exec("UNLOCK TABLES");
        } catch (Throwable $e) {
            Logger::warning("MyISAM READ LOCK bırakılamadı: " . $e->getMessage());
        }
    }
}

/**
 * MERKEZİ YEDEKLEME MOTORU
 */
function perform_backup(PDO $pdo, string $db_name, string $backup_dir, array $config, mixed $lock_handle, ?callable $progress_callback = null): string {
    // Backup yalnızca ortak veritabanı kilidi tutulurken çalıştırılır.
    require_database_operation_lock($lock_handle, $backup_dir);
    update_system_lock_heartbeat($lock_handle);

    // MyISAM için onarım ve ayrı bağlantıda READ LOCK uygulanır.
    repair_myisam_tables_before_backup($pdo, $db_name);
    update_system_lock_heartbeat($lock_handle);
    $myisam_lock_pdo = null;
    SchemaCache::clear();
    check_sufficient_disk_space($pdo, $db_name, $backup_dir);

    try {
        $lock_info = acquire_myisam_read_locks(
            $config['db_host'],
            $config['db_user'],
            $config['db_pass'],
            $db_name
        );
        $myisam_lock_pdo = $lock_info['pdo'];
        update_system_lock_heartbeat($lock_handle);
    } catch (Throwable $e) {
        release_myisam_read_locks($myisam_lock_pdo);
        throw $e;
    }

    // Tüm tablo sorguları aynı InnoDB snapshot'ından okunur.
    $snapshot_started = false;
    try {
        $pdo->exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
        $pdo->exec("START TRANSACTION WITH CONSISTENT SNAPSHOT");
        $snapshot_started = true;
        update_system_lock_heartbeat($lock_handle);
    } catch (Throwable $e) {
        safe_transaction_rollback($pdo);
        throw new Exception(
            "Tutarlı backup snapshot'ı başlatılamadı. InnoDB/REPEATABLE READ desteğini kontrol edin: " .
            $e->getMessage(),
            0,
            $e
        );
    }

    $stmtTables = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'");
    $stmtTables->execute([$db_name]);
    $tables = $stmtTables->fetchAll(PDO::FETCH_COLUMN);
    $stmtTables->closeCursor();

    $total_tables = count($tables);

    $backup_time_string = gmdate('Y-m-d_H-i') . 'UTC';
    $base_gz_file = $backup_dir . '/' . $db_name . '_' . $backup_time_string;
    $target_gz_file = $base_gz_file . '.sql.gz';
    $dup_counter = 1;

    while (file_exists($target_gz_file)) {
        $target_gz_file = $base_gz_file . '_' . $dup_counter . '.sql.gz';
        $dup_counter++;
    }

    $tmp_gz_file = $target_gz_file . '.tmp';

    $gz_level = get_dynamic_system_load();
    $gz = gzopen($tmp_gz_file, "w{$gz_level}");
    if (!$gz) {
        throw new Exception("Geçici sıkıştırılmış yedek dosyası oluşturulamadı.");
    }

    $start_time = microtime(true);
    $processed_rows_total = 0;
    $table_index = 0;

    $update_progress = function(string $status, string $current_table = '', string $error_msg = '') use (&$table_index, $total_tables, &$processed_rows_total, $start_time, $tmp_gz_file, $target_gz_file, $progress_callback) {
        $now = microtime(true);
        $elapsed = max(0.1, $now - $start_time);
        $bytes_written = is_file($tmp_gz_file) ? filesize($tmp_gz_file) : 0;

        $percent = ($total_tables > 0) ? min(100, round(($table_index / $total_tables) * 100)) : 0;
        if ($status === 'completed') $percent = 100;

        $rows_per_sec = ($elapsed > 0) ? round($processed_rows_total / $elapsed) : 0;
        $mb_per_sec = ($elapsed > 0) ? round(($bytes_written / (1024 * 1024)) / $elapsed, 2) : 0;

        $eta_seconds = ($percent > 0 && $percent < 100) ? round(($elapsed / $percent) * (100 - $percent)) : 0;

        if ($progress_callback !== null) {
            $progress_callback([
                'status'                      => $status,
                'percent'                     => $percent,
                'current_table'               => $current_table,
                'current_table_index'         => $table_index,
                'total_tables'                => $total_tables,
                'processed_rows'              => $processed_rows_total,
                'elapsed_seconds'             => round($elapsed),
                'estimated_remaining_seconds' => $eta_seconds,
                'speed_rows_per_second'       => $rows_per_sec,
                'speed_mb_per_second'         => $mb_per_sec,
                'bytes_written'               => $bytes_written,
                'formatted_bytes'             => format_bytes($bytes_written),
                'file_name'                   => basename($target_gz_file),
                'error_message'               => $error_msg,
                'updated_at'                  => date('Y-m-d H:i:s')
            ]);
        }
    };

    try {
        $update_progress('running', $tables[0] ?? '');
        safe_gzwrite($gz, "-- VEDO MYSQL BACKUP [FORMAT v" . VEDO_BACKUP_FORMAT . "]\n-- DB: {$db_name}\n-- TIME: " . date('Y-m-d H:i:s') . "\n-- CONSISTENT SNAPSHOT: REPEATABLE READ / WITH CONSISTENT SNAPSHOT\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n\n");

        foreach ($tables as $t) {
            $table_index++;
            update_system_lock_heartbeat($lock_handle);
            $update_progress('running', $t);

            export_single_table_to_stream(
                $pdo,
                $t,
                $gz,
                $db_name,
                $processed_rows_total,
                function() use ($update_progress, $t) {
                    $update_progress('running', $t);
                },
                $config['max_insert_rows']
            );
        }

        $update_progress('running', 'Database Objects (Views/Triggers/Functions)');
        export_database_objects_to_stream($pdo, $db_name, $gz);

        // Snapshot tamamen tüketildi; DB transaction'ını kontrollü şekilde kapat.
        if ($snapshot_started && $pdo->inTransaction()) {
            $pdo->commit();
            $snapshot_started = false;
        }

        safe_gzwrite($gz, "\nSET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n");

        if (!gzclose($gz)) {
            throw new Exception("Gzip dosyası kapatılırken hata oluştu.");
        }
        $gz = null;

        if (!@rename($tmp_gz_file, $target_gz_file)) {
            throw new Exception("Geçici gzip dosyası asıl hedefe taşınamadı!");
        }

        verify_and_checksum_gzip($target_gz_file);
        limit_backup_files($backup_dir, $config['max_backups']);

        release_myisam_read_locks($myisam_lock_pdo);
        $myisam_lock_pdo = null;

        $update_progress('completed');
        return $target_gz_file;

    } catch (Throwable $e) {
        release_myisam_read_locks($myisam_lock_pdo);
        $myisam_lock_pdo = null;
        if ($snapshot_started) {
            safe_transaction_rollback($pdo);
        }
        if (is_resource($gz)) {
            @gzclose($gz);
        }
        if (is_file($tmp_gz_file)) {
            @unlink($tmp_gz_file);
        }
        if (is_file($target_gz_file)) {
            @unlink($target_gz_file);
        }
        $update_progress('failed', '', $e->getMessage());
        throw $e;
    }
}
function verify_and_checksum_gzip(string $file_path): string {
    if (!is_file($file_path)) throw new Exception("Yedek dosyası bulunamadı.");

    // Checksum sıkıştırılmış .gz byte'ları üzerinden hesaplanır.
    $ctx = hash_init('sha256');
    $fp = fopen($file_path, 'rb');
    if (!$fp) throw new Exception("Yedek dosyası okuma modunda açılamadı!");

    while (!feof($fp)) {
        $chunk = fread($fp, 1024 * 1024);
        if ($chunk === false) {
            fclose($fp);
            throw new Exception("Yedek dosyası okunurken hata oluştu!");
        }
        if ($chunk !== '') {
            hash_update($ctx, $chunk);
        }
    }
    fclose($fp);

    $hash = hash_final($ctx);
    $sha_path = $file_path . '.sha256';

    if (!safe_file_put_contents($sha_path, $hash . "  " . basename($file_path) . "\n", LOCK_EX)) {
        throw new Exception("SHA256 imza dosyası yazılamadı!");
    }

    return $hash;
}
function verify_backup_checksum(string $file_path): string {
    if (!is_file($file_path)) throw new Exception("Yedek dosyası bulunamadı.");
    if (!validate_backup_filename(basename($file_path))) {
        throw new Exception("Yalnızca .sql.gz yedek dosyaları doğrulanabilir.");
    }

    $sha_file = $file_path . '.sha256';
    if (!is_file($sha_file)) throw new Exception("Checksum (.sha256) dosyası bulunamadı!");

    $sha_content = trim((string)file_get_contents($sha_file));
    $parts = preg_split('/\s+/', $sha_content);
    $expected_hash = $parts[0] ?? '';

    if (!preg_match('/^[a-f0-9]{64}$/i', $expected_hash)) {
        throw new Exception("Geçersiz checksum dosyası biçimi.");
    }

    // 1) Ham .gz byte'larının SHA256 değerini doğrula.
    $ctx = hash_init('sha256');
    $fp = fopen($file_path, 'rb');
    if (!$fp) throw new Exception("Yedek okunamadı!");

    try {
        while (!feof($fp)) {
            $chunk = fread($fp, 1024 * 1024);
            if ($chunk === false) {
                throw new Exception("Yedek okunurken hata oluştu!");
            }
            if ($chunk !== '') {
                hash_update($ctx, $chunk);
            }
        }
    } finally {
        fclose($fp);
    }

    $current_hash = hash_final($ctx);

    if (!hash_equals($expected_hash, $current_hash)) {
        throw new Exception("Checksum uyuşmazlığı! Dosya içeriği bozulmuş veya değiştirilmiş.");
    }

    // 2) Gzip akışının gerçekten açılabildiğini ve sonuna kadar okunabildiğini doğrula.
    $gz = @gzopen($file_path, 'rb');
    if (!$gz) {
        throw new Exception("Gzip arşivi açılamadı! Dosya bozulmuş olabilir.");
    }

    try {
        while (!gzeof($gz)) {
            $chunk = gzread($gz, 1024 * 1024);
            if ($chunk === false) {
                throw new Exception("Gzip bütünlük kontrolü başarısız! Arşiv okunamadı.");
            }
            // gzread() boş dönebilir; gzeof() sonraki döngüde EOF'yi belirler.
        }
    } finally {
        gzclose($gz);
    }

    return $current_hash;
}
function verify_database_integrity_after_restore(PDO $pdo, string $db_name, bool $quick = true, bool $analyze = false): array {
    $report = [
        'status' => 'OK',
        'tables_checked' => 0,
        'fk_issues' => 0,
        'errors' => []
    ];
    try {
        $stmtTables = $pdo->query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'");
        $tables = $stmtTables ? $stmtTables->fetchAll(PDO::FETCH_COLUMN) : [];
        if ($stmtTables) $stmtTables->closeCursor();

        $report['tables_checked'] = count($tables);
        $check_sql = $quick ? "CHECK TABLE `%s` QUICK" : "CHECK TABLE `%s`";

        foreach ($tables as $t) {
            if (!preg_match('/^[a-zA-Z0-9_]+$/', $t)) continue;

            $chkStmt = $pdo->query(sprintf($check_sql, $t));
            if ($chkStmt) {
                $rows = $chkStmt->fetchAll(PDO::FETCH_ASSOC);
                $chkStmt->closeCursor();

                foreach ($rows as $row) {
                    $msgType = strtolower($row['Msg_type'] ?? '');
                    $msgText = strtolower($row['Msg_text'] ?? '');
                    if ($msgType === 'error' || ($msgType === 'status' && $msgText !== 'ok' && $msgText !== 'table is already up to date')) {
                        $report['errors'][] = "Tablo [$t]: {$row['Msg_text']}";
                        $report['status'] = 'WARNING';
                    }
                }
            }

            if ($analyze) {
                try {
                    $pdo->exec("ANALYZE TABLE `{$t}`");
                } catch (Exception $e) {}
            }
        }

        try {
            $fkStmt = $pdo->prepare("
                SELECT CONSTRAINT_NAME, TABLE_NAME, REFERENCED_TABLE_NAME,
                       COLUMN_NAME, REFERENCED_COLUMN_NAME, ORDINAL_POSITION
                FROM information_schema.KEY_COLUMN_USAGE
                WHERE TABLE_SCHEMA = ? AND REFERENCED_TABLE_NAME IS NOT NULL
                ORDER BY TABLE_NAME, CONSTRAINT_NAME, ORDINAL_POSITION
            ");
            $fkStmt->execute([$db_name]);
            $fkRows = $fkStmt->fetchAll(PDO::FETCH_ASSOC);
            $fkStmt->closeCursor();

            $groups = [];
            foreach ($fkRows as $fk) {
                $key = (string)$fk['TABLE_NAME'] . "\0" . (string)$fk['CONSTRAINT_NAME'];
                $groups[$key]['table'] = (string)$fk['TABLE_NAME'];
                $groups[$key]['referenced_table'] = (string)$fk['REFERENCED_TABLE_NAME'];
                $groups[$key]['columns'][] = [
                    'local' => (string)$fk['COLUMN_NAME'],
                    'remote' => (string)$fk['REFERENCED_COLUMN_NAME'],
                    'position' => (int)$fk['ORDINAL_POSITION']
                ];
            }

            foreach ($groups as $groupKey => $fk) {
                $localTable = (string)$fk['table'];
                $remoteTable = (string)$fk['referenced_table'];
                if (!preg_match('/^[A-Za-z0-9_$]+$/', $localTable) || !preg_match('/^[A-Za-z0-9_$]+$/', $remoteTable)) continue;
                usort($fk['columns'], static fn(array $x, array $y): int => $x['position'] <=> $y['position']);

                $join = [];
                $nonnull = [];
                $firstRemote = '';
                foreach ($fk['columns'] as $column) {
                    $local = $column['local']; $remote = $column['remote'];
                    if (!preg_match('/^[A-Za-z0-9_$]+$/', $local) || !preg_match('/^[A-Za-z0-9_$]+$/', $remote)) continue 2;
                    $localQ = '`' . str_replace('`', '``', $local) . '`';
                    $remoteQ = '`' . str_replace('`', '``', $remote) . '`';
                    $join[] = 't.' . $localQ . ' = r.' . $remoteQ;
                    $nonnull[] = 't.' . $localQ . ' IS NOT NULL';
                    if ($firstRemote === '') $firstRemote = $remoteQ;
                }
                if (!$join || $firstRemote === '') continue;

                $sql = 'SELECT 1 FROM `' . str_replace('`', '``', $localTable) . '` t ' .
                       'LEFT JOIN `' . str_replace('`', '``', $remoteTable) . '` r ON ' . implode(' AND ', $join) .
                       ' WHERE ' . implode(' AND ', $nonnull) . ' AND r.' . $firstRemote . ' IS NULL LIMIT 1';
                $checkFk = $pdo->query($sql);
                if ($checkFk) {
                    $hasViolation = ($checkFk->fetchColumn() !== false);
                    $checkFk->closeCursor();
                    if ($hasViolation) {
                        $report['fk_issues']++;
                        $report['errors'][] = "FK İhlali: {$localTable} -> {$remoteTable} (constraint={$groupKey})";
                        $report['status'] = 'WARNING';
                    }
                }
            }
        } catch (Exception $eFK) {
            $report['errors'][] = 'FK bütünlük kontrolü çalıştırılamadı: ' . $eFK->getMessage();
            $report['status'] = 'WARNING';
        }

    } catch (Exception $e) {
        $report['status'] = 'ERROR';
        $report['errors'][] = $e->getMessage();
    }
    return $report;
}

/**
 * GERİ YÜKLEME ÖNCESİ VERİTABANI TEMİZLEME
 * Restore'un ilk chunk'ında bir kez çağrılır; sonraki chunk'lar dokunmaz.
 */
function clear_database_for_restore(PDO $pdo, string $db_name): array {
    $dropped = [];
    $failed = [];

    try {
        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');

        $stmt = $pdo->prepare("SELECT TABLE_NAME, TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_TYPE, TABLE_NAME");
        $stmt->execute([$db_name]);
        $objects = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        foreach ($objects as $object) {
            $name = (string)($object['TABLE_NAME'] ?? '');
            $type = strtoupper((string)($object['TABLE_TYPE'] ?? ''));
            if ($name === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $name)) {
                $failed[] = ['object'=>$name, 'type'=>$type, 'reason'=>'Geçersiz nesne adı'];
                continue;
            }
            $q = '`' . str_replace('`', '``', $name) . '`';
            try {
                $pdo->exec($type === 'VIEW' ? "DROP VIEW IF EXISTS {$q}" : "DROP TABLE IF EXISTS {$q}");
                $dropped[] = ['object'=>$name, 'type'=>$type];
            } catch (Throwable $e) {
                $failed[] = ['object'=>$name, 'type'=>$type, 'reason'=>$e->getMessage()];
            }
        }

        $queries = [
            ['sql' => "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ?", 'type' => 'TRIGGER', 'drop' => 'DROP TRIGGER IF EXISTS `%s`'],
            ['sql' => "SELECT ROUTINE_NAME, ROUTINE_TYPE FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ?", 'type' => 'ROUTINE', 'drop' => null],
            ['sql' => "SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ?", 'type' => 'EVENT', 'drop' => 'DROP EVENT IF EXISTS `%s`'],
        ];

        // Triggers
        $stmt = $pdo->prepare($queries[0]['sql']);
        $stmt->execute([$db_name]);
        $triggers = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $stmt->closeCursor();
        foreach ($triggers as $name) {
            $name=(string)$name;
            if ($name!=='' && preg_match('/^[A-Za-z0-9_$]+$/',$name)) {
                try { $pdo->exec(sprintf($queries[0]['drop'],$name)); $dropped[]=['object'=>$name,'type'=>'TRIGGER']; }
                catch(Throwable $e){ $failed[]=['object'=>$name,'type'=>'TRIGGER','reason'=>$e->getMessage()]; }
            }
        }

        // Procedures / functions
        $stmt = $pdo->prepare($queries[1]['sql']);
        $stmt->execute([$db_name]);
        $routines = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        foreach ($routines as $r) {
            $name=(string)($r['ROUTINE_NAME']??''); $type=strtoupper((string)($r['ROUTINE_TYPE']??''));
            if ($name!=='' && preg_match('/^[A-Za-z0-9_$]+$/',$name)) {
                $q='`'.str_replace('`','``',$name).'`';
                try { $pdo->exec($type==='FUNCTION' ? "DROP FUNCTION IF EXISTS {$q}" : "DROP PROCEDURE IF EXISTS {$q}"); $dropped[]=['object'=>$name,'type'=>$type]; }
                catch(Throwable $e){ $failed[]=['object'=>$name,'type'=>$type,'reason'=>$e->getMessage()]; }
            }
        }

        // Events
        $stmt = $pdo->prepare($queries[2]['sql']);
        $stmt->execute([$db_name]);
        $events = $stmt->fetchAll(PDO::FETCH_COLUMN);
        $stmt->closeCursor();
        foreach ($events as $name) {
            $name=(string)$name;
            if ($name!=='' && preg_match('/^[A-Za-z0-9_$]+$/',$name)) {
                try { $pdo->exec(sprintf($queries[2]['drop'],$name)); $dropped[]=['object'=>$name,'type'=>'EVENT']; }
                catch(Throwable $e){ $failed[]=['object'=>$name,'type'=>'EVENT','reason'=>$e->getMessage()]; }
            }
        }

        $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
    } catch (Throwable $e) {
        try { $pdo->exec('SET FOREIGN_KEY_CHECKS=1'); } catch (Throwable $ignored) {}
        throw $e;
    }

    if ($failed) {
        throw new Exception('Restore öncesi veritabanı tamamen temizlenemedi: ' . json_encode($failed, JSON_UNESCAPED_UNICODE));
    }
    Logger::warning("Restore öncesi veritabanı temizlendi: {$db_name}; silinen nesne: " . count($dropped));
    return $dropped;
}
function verify_restore_source_integrity(string $file_path): string {
    $hash = verify_backup_checksum($file_path);
    return strtolower($hash);
}

/**
 * RESTORE ÖNCESİ TEMİZLİK SONU KONTROLÜ
 * Database'in kendisi DROP edilmez; içindeki tüm restore nesneleri kaldırılır.
 * Restore başlamadan önce TABLES / TRIGGERS / ROUTINES / EVENTS tamamı 0 olmalıdır.
 */
function verify_database_is_empty_for_restore(PDO $pdo, string $db_name): array {
    $counts = [
        'tables' => 0,
        'triggers' => 0,
        'routines' => 0,
        'events' => 0,
    ];

    $checks = [
        'tables' => "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?",
        'triggers' => "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ?",
        'routines' => "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ?",
        'events' => "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ?",
    ];

    foreach ($checks as $key => $sql) {
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$db_name]);
        $counts[$key] = (int)$stmt->fetchColumn();
        $stmt->closeCursor();
    }

    if (array_sum($counts) !== 0) {
        throw new Exception(
            'Restore öncesi veritabanı tamamen boş değil. ' .
            sprintf(
                'TABLES=%d, TRIGGERS=%d, ROUTINES=%d, EVENTS=%d',
                $counts['tables'],
                $counts['triggers'],
                $counts['routines'],
                $counts['events']
            )
        );
    }

    return $counts;
}

function restore_parse_buffer(string $buffer, string &$queryBuffer, bool &$inString, string &$stringChar, bool &$inCommentMulti, bool &$inCommentSingle, bool &$escaped, string &$currentDelimiter, string &$lineBuffer = ''): array {
    $extractedQueries = [];
    $bufLen = strlen($buffer);

    for ($i = 0; $i < $bufLen; $i++) {
        $char = $buffer[$i];
        $nextChar = ($i + 1 < $bufLen) ? $buffer[$i + 1] : '';

        if (strlen($queryBuffer) > VEDO_QUERY_BUFFER_MAX) {
            throw new Exception("Sorgu arabelleği çok büyüdü (50MB+). SQL dosyasını kontrol edin.");
        }

        /*
         * DELIMITER satırını ayrı bir state ile takip ediyoruz.
         * Böylece "DELIMITER //" ifadesi gzip chunk sınırında bölünse bile
         * bir sonraki chunk geldiğinde eksiksiz olarak değerlendirilebilir.
         * lineBuffer yalnızca aktif satırı tutar; SQL queryBuffer'a ayrıca
         * yazıldığı için normal SQL içeriğinin kaybolmasına neden olmaz.
         */
        // Satır state'i string/comment durumundan bağımsız tutulur; böylece
        // chunk sınırında yarım kalan DELIMITER satırı asla kaybolmaz.
        $lineBuffer .= $char;
        if (strlen($lineBuffer) > 4096) {
            $lineBuffer = substr($lineBuffer, -4096);
        }

        if ($inCommentMulti) {
            $queryBuffer .= $char;
            if ($char === '*' && $nextChar === '/') {
                $queryBuffer .= '/';
                $i++;
                $inCommentMulti = false;
            }
            continue;
        }

        if ($inCommentSingle) {
            $queryBuffer .= $char;
            if ($char === "\n" || $char === "\r") {
                $inCommentSingle = false;
                $lineBuffer = '';
            }
            continue;
        }

        if ($inString) {
            $queryBuffer .= $char;
            if ($escaped) {
                $escaped = false;
            } elseif ($char === '\\') {
                $escaped = true;
            } elseif ($char === $stringChar) {
                $inString = false;
                $stringChar = '';
            }
            continue;
        }

        if ($char === '/' && $nextChar === '*') {
            $queryBuffer .= '/*';
            $i++;
            $inCommentMulti = true;
            continue;
        }

        $isDashComment = false;
        if ($char === '-' && $nextChar === '-') {
            $afterDashPos = $i + 2;
            if ($afterDashPos >= $bufLen || in_array($buffer[$afterDashPos], [' ', "\t", "\r", "\n"], true)) {
                $isDashComment = true;
            }
        }
        if ($isDashComment || $char === '#') {
            $queryBuffer .= $char;
            $inCommentSingle = true;
            continue;
        }

        if ($char === "'" || $char === '"' || $char === '`') {
            $queryBuffer .= $char;
            $inString = true;
            $stringChar = $char;
            $escaped = false;
            continue;
        }

        $queryBuffer .= $char;

        /* DELIMITER yalnızca satırın tamamı görüldüğünde değerlendirilir. */
        if ($char === "\n" || $char === "\r") {
            $line = trim($lineBuffer);
            if (preg_match('/^DELIMITER[ \t]+([^\s\r\n]+)$/i', $line, $matches)) {
                $newDelimiter = trim($matches[1]);
                if ($newDelimiter === '' || strlen($newDelimiter) > 32 || preg_match('/[\x00-\x1F\x7F]/', $newDelimiter)) {
                    throw new Exception('Geçersiz DELIMITER yönergesi tespit edildi.');
                }
                // Sadece yönerge satırını queryBuffer'dan çıkar.
                $lineLength = strlen($lineBuffer);
                $queryBufferLength = strlen($queryBuffer);
                if ($lineLength <= $queryBufferLength) {
                    $queryBuffer = substr($queryBuffer, 0, $queryBufferLength - $lineLength);
                }
                $currentDelimiter = $newDelimiter;
                $lineBuffer = '';
                continue;
            }
            $lineBuffer = '';
        }

        /*
         * DELIMITER yönergesinin ilk satır parçası tamamlanmadan mevcut
         * delimiter ile SQL'i bölme. Bu kontrol yalnızca satır başındaki
         * yönerge adayları için geçerlidir.
         */
        $directiveCandidate = ltrim($lineBuffer);
        if ($directiveCandidate !== '' && preg_match('/^DELIMITER(?:[ \t]+[^\r\n]*)?$/i', $directiveCandidate)) {
            continue;
        }

        $delimLen = strlen($currentDelimiter);
        if ($delimLen > 0 && strlen($queryBuffer) >= $delimLen && substr($queryBuffer, -$delimLen) === $currentDelimiter) {
            $sqlToExec = trim(substr($queryBuffer, 0, -$delimLen));
            if ($sqlToExec !== '') {
                $extractedQueries[] = $sqlToExec;
            }
            $queryBuffer = '';
            $lineBuffer = '';
        }
    }

    return $extractedQueries;
}
// Kapanmamış string/comment/delimiter veya yarım DELIMITER yönergesi varsa restore'u reddeder.
function finalize_restore_parser(string &$queryBuffer, bool $inString, string $stringChar, bool $inCommentMulti, bool $inCommentSingle, bool $escaped, string $currentDelimiter, string $delimiterLineBuffer = ''): ?string {
    if ($inString) {
        throw new Exception('Restore dosyası EOF noktasında kapanmamış SQL stringi içeriyor.');
    }
    if ($inCommentMulti) {
        throw new Exception('Restore dosyası EOF noktasında kapanmamış çok satırlı yorum içeriyor.');
    }
    if ($escaped) {
        throw new Exception('Restore dosyası EOF noktasında yarım escape durumu içeriyor.');
    }
    if ($delimiterLineBuffer !== '') {
        $line = trim($delimiterLineBuffer);
        if ($line !== '' && preg_match('/^DELIMITER(?:[ \t]+.*)?$/i', $line)) {
            throw new Exception('Restore dosyası EOF noktasında tamamlanmamış DELIMITER yönergesi içeriyor.');
        }
    }
    if ($currentDelimiter !== ';') {
        throw new Exception("Restore dosyası EOF noktasında DELIMITER '{$currentDelimiter}' durumunda kaldı; SQL komutu düzgün kapatılmamış.");
    }

    $remaining = trim($queryBuffer);
    $queryBuffer = '';
    if ($remaining === '') {
        return null;
    }

    if (preg_match('/^DELIMITER(?:[ \t]+.*)?$/is', $remaining)) {
        throw new Exception('Restore dosyası EOF noktasında tamamlanmamış DELIMITER yönergesi içeriyor.');
    }

    return $remaining;
}
function validate_restore_sql_statement(string $sql, bool $throw = true): bool {
    $allowed_sql_regexes = [
        '/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?TABLE\s+/i',
        '/^DROP\s+(?:TEMPORARY\s+)?TABLE(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+/i',
        '/^DROP\s+VIEW(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+TRIGGER\s+/i', '/^DROP\s+TRIGGER(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+/i', '/^DROP\s+FUNCTION(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+/i', '/^DROP\s+PROCEDURE(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+EVENT\s+/i', '/^DROP\s+EVENT(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+SEQUENCE\s+/i', '/^DROP\s+SEQUENCE(?:\s+IF\s+EXISTS)?\s+/i',
        '/^CREATE\s+(?:UNIQUE\s+)?(?:FULLTEXT\s+|SPATIAL\s+)?INDEX\s+/i', '/^DROP\s+INDEX(?:\s+IF\s+EXISTS)?\s+/i',
        '/^RENAME\s+TABLE\s+/i',
        '/^(?:INSERT(?:\s+IGNORE)?|UPDATE|DELETE|REPLACE)\s+/i', '/^TRUNCATE\s+(?:TABLE\s+)?/i',
        '/^ALTER\s+TABLE\s+/i', '/^(?:ANALYZE|OPTIMIZE|CHECK)\s+TABLE\s+/i',
        '/^(?:LOCK|UNLOCK)\s+TABLES(?:\s+|$)/i',
    ];
    // Yalnızca bu backup motorunun üretebileceği ve restore için gerekli SET değişkenleri kabul edilir.
    $allowed_set_variables = [
        'FOREIGN_KEY_CHECKS', 'UNIQUE_CHECKS', 'SQL_MODE', 'TIME_ZONE', 'NAMES',
        'CHARACTER_SET_CLIENT', 'CHARACTER_SET_RESULTS', 'CHARACTER_SET_CONNECTION',
        'AUTOCOMMIT'
    ];

    $sql_trimmed = (string)$sql;
    $sql_trimmed = preg_replace('/^\xEF\xBB\xBF/', '', $sql_trimmed) ?? $sql_trimmed;
    $clean_sql_check = preg_replace('/\/\*.*?\*\//s', '', $sql_trimmed);
    $clean_sql_check = preg_replace('/(--|#)[^\r\n]*/', '', (string)$clean_sql_check);
    $clean_sql_check = preg_replace('/^(?:(?:\s+)|(?:\\[nrt])+)+/u', '', (string)$clean_sql_check) ?? ltrim((string)$clean_sql_check);
    $clean_sql_check = ltrim($clean_sql_check);
    if ($clean_sql_check === '') return true;

    $is_allowed = false;
    foreach ($allowed_sql_regexes as $pattern) {
        if (preg_match($pattern, $clean_sql_check)) { $is_allowed = true; break; }
    }
    if (!$is_allowed && str_starts_with(strtoupper($clean_sql_check), 'SET ')) {
        $sql_upper = strtoupper($clean_sql_check);
        if (!str_contains($sql_upper, 'GLOBAL') && !str_contains($sql_upper, 'PERSIST')) {
            foreach ($allowed_set_variables as $set_var) {
                if (preg_match('/^\s*SET\s+(SESSION\s+|@@SESSION\.|@@LOCAL\.|@@)?' . preg_quote($set_var, '/') . '\s*=/i', $clean_sql_check)) {
                    $is_allowed = true; break;
                }
            }
        }
    }
    if (!$is_allowed && $throw) {
        $sql_summary = summarize_sql_for_log($sql_trimmed);
        $error_message = 'Güvenlik Engeli: İzin verilmeyen SQL komutu tespit edildi! (' . $sql_summary . ')';
        Logger::error($error_message);
        throw new Exception($error_message);
    }
    return $is_allowed;
}
function validate_backup_restore_compatibility(string $file_path): array {
    verify_backup_checksum($file_path);
    $gz = @gzopen($file_path, 'rb');
    if (!$gz) throw new Exception('Gzip arşivi test restore doğrulaması için açılamadı.');

    $query_buffer = ''; $in_string = false; $string_char = ''; $in_comment_multi = false;
    $in_comment_single = false; $escaped = false; $current_delimiter = ';'; $delimiter_line_buffer = ''; $query_count = 0;
    try {
        while (!gzeof($gz)) {
            $chunk = gzread($gz, VEDO_RESTORE_CHUNK_BYTES);
            if ($chunk === false) throw new Exception('Gzip test restore doğrulaması okunurken hata oluştu.');
            if ($chunk === '') continue;
            $queries = restore_parse_buffer($chunk, $query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer);
            foreach ($queries as $query) {
                validate_restore_sql_statement($query, true);
                $query_count++;
            }
        }
        $final_query = finalize_restore_parser($query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer);
        if ($final_query !== null) {
            validate_restore_sql_statement($final_query, true);
            $query_count++;
        }
    } finally {
        gzclose($gz);
    }
    return ['status'=>'OK', 'queries_validated'=>$query_count];
}
function extract_restore_table_name(string $sql): string {
    $sql = trim($sql);
    $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql) ?? $sql;
    $sql = preg_replace('/^\s+/', '', $sql) ?? $sql;

    $patterns = [
        '/^INSERT(?:\s+IGNORE)?\s+INTO\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^REPLACE(?:\s+INTO)?\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^UPDATE\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^DELETE\s+FROM\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^(?:CREATE|DROP|ALTER)\s+(?:TEMPORARY\s+)?(?:TABLE|VIEW|TRIGGER|FUNCTION|PROCEDURE|EVENT)(?:\s+IF\s+(?:NOT\s+)?EXISTS)?\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^TRUNCATE\s+(?:TABLE\s+)?((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $sql, $m)) {
            $table = trim((string)$m[1]);
            $table = preg_replace('/^`([^`]*)`$/', '$1', $table) ?? $table;
            if (str_contains($table, '.')) {
                $parts = preg_split('/\s*\.\s*/', $table);
                $table = (string)end($parts);
                $table = preg_replace('/^`([^`]*)`$/', '$1', $table) ?? $table;
            }
            return $table;
        }
    }

    return '';
}

function restore_execute_sql(PDO &$pdo, array $queries, int &$processed_tables_count, int &$processed_rows_count, string $backup_dir, array $config = [], ?string &$current_table = null): int {
    $executed = 0;
    $max_retries = 5;

    foreach ($queries as $sql) {
        $sql_trimmed = (string)$sql;
        $detected_table = extract_restore_table_name($sql_trimmed);
        if ($detected_table !== '' && $current_table !== null) {
            $current_table = $detected_table;
        }
        $sql_trimmed = preg_replace('/^\xEF\xBB\xBF/', '', $sql_trimmed) ?? $sql_trimmed;
        $sql_trimmed = preg_replace('/^(?:(?:\s+)|(?:\\[nrt])+)+/u', '', $sql_trimmed) ?? ltrim($sql_trimmed);
        validate_restore_sql_statement($sql_trimmed, true);

        $attempt = 0;
        $success = false;
        $last_error_message = '';

        while ($attempt < $max_retries && !$success) {
            $attempt++;
            try {
                $pdo->exec($sql);
                $success = true;
            } catch (Exception $e) {
                $last_error_message = $e->getMessage();
                $error_code = (int)$e->getCode();

                $transient_codes = [1205, 1213, 2006, 2013, 40001];
                $is_transient = in_array($error_code, $transient_codes, true) ||
                                stripos($last_error_message, 'deadlock') !== false ||
                                stripos($last_error_message, 'lock wait timeout') !== false ||
                                stripos($last_error_message, 'gone away') !== false ||
                                stripos($last_error_message, 'lost connection') !== false;

                if ($is_transient) {
                    if ($pdo->inTransaction()) {
                        // Aktif chunk transaction'ı sırasında PDO'yu değiştirmek transaction state'ini kaybettirir.
                        // Aktif transaction varken bağlantıyı değiştirmek güvenli olmadığından yeniden deneme yapılmaz.
                        break;
                    }
                    if (!empty($config)) {
                        try {
                            $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], true, $config['use_persistent_pdo'] ?? false);
                            $pdo->exec("SET FOREIGN_KEY_CHECKS=0;");
                            $pdo->exec("SET UNIQUE_CHECKS=0;");
                        } catch (Exception $reEx) {
                            Logger::warning("Yeniden PDO bağlantı kurulum hatası: " . $reEx->getMessage());
                        }
                    }
                    if ($attempt < $max_retries) {
                        $delay_microseconds = (int)(200000 * pow(2, $attempt - 1));
                        usleep($delay_microseconds);
                        continue;
                    }
                }
                break;
            }
        }

        if (!$success) {
            Logger::error("SQL Hatası (Deneme {$attempt}): {$last_error_message} | Sorgu: " . summarize_sql_for_log($sql_trimmed));
            throw new Exception("SQL Çalıştırma Hatası: " . $last_error_message);
        }

        $executed++;
        restore_calculate_progress($sql, $processed_tables_count, $processed_rows_count);
    }
    return $executed;
}
function summarize_sql_for_log(string $sql): string {
    $sql = trim($sql);
    if ($sql === '') {
        return 'EMPTY';
    }

    $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql) ?? $sql;
    $sql = preg_replace('/\/\*.*?\*\//s', ' ', $sql) ?? $sql;
    $sql = preg_replace('/(?:--|#)[^\r\n]*/', ' ', $sql) ?? $sql;
    $sql = trim((string)(preg_replace('/\s+/u', ' ', $sql) ?? $sql));

    $type = strtoupper((string)(preg_match('/^([A-Z]+)/i', $sql, $m) ? $m[1] : 'SQL'));
    $object = '';

    $patterns = [
        '/^INSERT(?:\s+IGNORE)?\s+INTO\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^(?:UPDATE|DELETE\s+FROM|REPLACE(?:\s+INTO)?)\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i',
        '/^(?:CREATE|DROP|ALTER)\s+(?:TEMPORARY\s+)?(?:TABLE|VIEW|TRIGGER|FUNCTION|PROCEDURE|EVENT)(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[A-Za-z0-9_$]+)(?:\s*\.\s*(?:`[^`]+`|[A-Za-z0-9_$]+))?)/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $sql, $m)) {
            $object = trim($m[1]);
            break;
        }
    }

    if ($object !== '') {
        return $type . ' ' . $object;
    }

    return $type;
}

function restore_calculate_progress(string $sql, int &$processed_tables_count, int &$processed_rows_count): void {
    $trimmed = ltrim($sql);
    if (strncasecmp($trimmed, 'INSERT INTO', 11) === 0) {
        $values_pos = stripos($trimmed, 'VALUES');
        if ($values_pos !== false) {
            $values_part = substr($trimmed, $values_pos + 6);
            $tuple_count = 0;
            $in_str = false;
            $str_c = '';
            $esc = false;
            $len = strlen($values_part);

            for ($i = 0; $i < $len; $i++) {
                $ch = $values_part[$i];
                if ($in_str) {
                    if ($esc) { $esc = false; }
                    elseif ($ch === '\\') { $esc = true; }
                    elseif ($ch === $str_c) { $in_str = false; }
                } else {
                    if ($ch === "'" || $ch === '"' || $ch === '`') {
                        $in_str = true;
                        $str_c = $ch;
                    } elseif ($ch === '(') {
                        $tuple_count++;
                    }
                }
            }
            $processed_rows_count += max(1, $tuple_count);
        } else {
            $processed_rows_count++;
        }
    } else {
        $upper_prefix = strtoupper(substr($trimmed, 0, 25));
        if (
            str_starts_with($upper_prefix, 'DROP TABLE') ||
            str_starts_with($upper_prefix, 'CREATE TABLE') ||
            str_starts_with($upper_prefix, 'CREATE VIEW') ||
            str_starts_with($upper_prefix, 'DROP VIEW') ||
            str_starts_with($upper_prefix, 'CREATE PROCEDURE') ||
            str_starts_with($upper_prefix, 'CREATE FUNCTION') ||
            str_starts_with($upper_prefix, 'CREATE TRIGGER') ||
            str_starts_with($upper_prefix, 'CREATE EVENT')
        ) {
            $processed_tables_count++;
        }
    }
}

// 6A. ARKA PLAN CLI İŞLERİ
// Panelden başlatılan uzun backup/restore işlemleri ayrı bir CLI PHP sürecinde yürütülür.
// Tarayıcı yalnızca job durumunu izler; uzun işlem HTTP request'ine bağlı değildir.
// 6A. ARKA PLAN CLI İŞ DURUMU
function write_cli_job_state(string $backup_dir, string $job_id, array $state): void {
    if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
        throw new Exception('Geçersiz CLI job ID.');
    }
    $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
    $tmp = $path . '.tmp';
    $state['job_id'] = $job_id;
    $state['updated_at'] = time();
    $json = json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
        @unlink($tmp);
        throw new Exception('CLI job durum dosyası yazılamadı.');
    }
}
function read_cli_job_state(string $backup_dir, string $job_id): array {
    if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) return [];
    $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
    if (!is_file($path)) return [];
    $data = json_decode((string)@file_get_contents($path), true);
    return is_array($data) ? $data : [];
}
function cleanup_stale_cli_job_states(string $backup_dir, int $max_age = 86400): void {
    $files = glob($backup_dir . '/.cli_job_*.json') ?: [];
    $now = time();

    foreach ($files as $path) {
        if (!is_file($path)) continue;
        $mtime = (int)@filemtime($path);
        if ($mtime > 0 && ($now - $mtime) > $max_age) {
            @unlink($path);
            @unlink($path . '.tmp');
        }
    }
}
function find_active_cli_job_states(string $backup_dir): array {
    $active = [];
    $files = glob($backup_dir . '/.cli_job_*.json') ?: [];

    foreach ($files as $path) {
        if (!is_file($path)) continue;
        $data = json_decode((string)@file_get_contents($path), true);
        if (!is_array($data)) continue;

        $status = (string)($data['status'] ?? '');
        if (!in_array($status, ['starting', 'verifying', 'waiting', 'running', 'clearing', 'restoring'], true)) {
            continue;
        }

        $name = basename($path);
        if (preg_match('/^\.cli_job_([a-f0-9]{32})\.json$/', $name, $m)) {
            $data['job_id'] = $m[1];
            $data['_mtime'] = (int)@filemtime($path);
            $active[] = $data;
        }
    }

    usort($active, static fn($a, $b) => ($b['_mtime'] ?? 0) <=> ($a['_mtime'] ?? 0));
    foreach ($active as &$job) unset($job['_mtime']);
    unset($job);

    return $active;
}
function assert_no_active_database_job(string $backup_dir, string $ignore_job_id = ''): void {
    cleanup_stale_cli_job_states($backup_dir);
    $active = find_active_cli_job_states($backup_dir);
    foreach ($active as $job) {
        $jobId = (string)($job['job_id'] ?? '');
        if ($ignore_job_id !== '' && $jobId === $ignore_job_id) {
            continue;
        }
        $status = (string)($job['status'] ?? '');
        $type = (string)($job['type'] ?? '');
        throw new Exception(sprintf(
            'Başka bir veritabanı işlemi aktif. Yeni işlem başlatılamaz. job_id=%s | type=%s | status=%s',
            $jobId !== '' ? $jobId : '-',
            $type !== '' ? $type : '-',
            $status !== '' ? $status : '-'
        ));
    }
}
// PAYLAŞIMLI HOST: CLI/exec/proc_open kullanılamıyorsa Web Worker yedeği kullanılabilir.
function detect_cli_worker_capability(): array {
    $result = [
        'available' => false,
        'reason' => '',
        'php_binary' => ''
    ];

    if (!function_exists('exec') && !function_exists('proc_open')) {
        $result['reason'] = 'exec() ve proc_open() kullanılabilir değil.';
        return $result;
    }

    try {
        $php = resolve_cli_php_binary();
        $result['php_binary'] = $php;

        // Gerçek bir yol bulunuyorsa doğrudan kullanılabilirlik kabul edilir.
        if ($php !== 'php' && $php !== 'php.exe') {
            $result['available'] = is_file($php) && is_executable($php);
            if (!$result['available']) {
                $result['reason'] = 'CLI PHP binary bulundu ancak çalıştırılabilir değil.';
            }
            return $result;
        }

        // PATH üzerinden bulunan php için kısa bir sürüm çağrısı ile doğrulama yapılır.
        if (function_exists('exec')) {
            $output = [];
            $exitCode = 1;
            @exec(escapeshellarg($php) . ' -r ' . escapeshellarg('echo PHP_SAPI;'), $output, $exitCode);
            if ($exitCode === 0 && trim(implode('', $output)) === 'cli') {
                $result['available'] = true;
                return $result;
            }
        }

        if (function_exists('proc_open')) {
            $descriptor = [
                0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w']
            ];
            $proc = @proc_open(
                escapeshellarg($php) . ' -r ' . escapeshellarg('echo PHP_SAPI;'),
                $descriptor,
                $pipes
            );
            if (is_resource($proc)) {
                $stdout = trim((string)stream_get_contents($pipes[1]));
                $stderr = trim((string)stream_get_contents($pipes[2]));
                foreach ($pipes as $pipe) {
                    if (is_resource($pipe)) @fclose($pipe);
                }
                $exitCode = @proc_close($proc);
                if ($exitCode === 0 && $stdout === 'cli') {
                    $result['available'] = true;
                    return $result;
                }
                $result['reason'] = $stderr !== '' ? $stderr : 'PHP CLI doğrulaması başarısız.';
            }
        }
    } catch (Throwable $e) {
        $result['reason'] = $e->getMessage();
    }

    if ($result['reason'] === '') {
        $result['reason'] = 'PHP CLI worker doğrulanamadı.';
    }
    return $result;
}
function build_web_backup_paths(string $backup_dir, string $db_name, string $prefix = ''): array {
    $suffix = gmdate('Y-m-d_H-i') . 'UTC';
    $base = $backup_dir . '/' . ($prefix !== '' ? $prefix . '_' : '') . $db_name . '_' . $suffix;
    $target = $base . '.sql.gz';
    $counter = 1;
    while (file_exists($target) || file_exists($target . '.tmp')) {
        $target = $base . '_' . $counter . '.sql.gz';
        $counter++;
    }
    return [
        'target' => $target,
        'tmp' => $target . '.tmp'
    ];
}
function get_web_worker_tables(PDO $pdo, string $db_name): array {
    $stmt = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME");
    $stmt->execute([$db_name]);
    $tables = array_values(array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN)));
    $stmt->closeCursor();
    return $tables;
}
// NOT: Web fallback, CLI'daki tek transaction/consistent snapshot modelinden farklı olarak tablo bazlı ilerler.
// Bunun nedeni shared hosting HTTP istekleri arasında aynı PDO transactionının güvenilir biçimde korunamamasıdır.
function web_backup_step(
    PDO $pdo,
    string $job_id,
    string $backup_dir,
    array $config,
    string $state_prefix = 'backup',
    ?array $state_override = null
): array {
    $state = $state_override ?? read_cli_job_state($backup_dir, $job_id);
    if (!$state) throw new Exception('Web Worker durum dosyası bulunamadı.');

    $tables = array_values(array_map('strval', $state[$state_prefix . '_tables'] ?? $state['tables'] ?? []));
    $indexKey = $state_prefix . '_table_index';
    $rowsKey = $state_prefix . '_processed_rows';
    $tmpKey = $state_prefix . '_tmp_file';
    $targetKey = $state_prefix . '_target_file';

    $index = (int)($state[$indexKey] ?? 0);
    $processedRows = (int)($state[$rowsKey] ?? 0);
    $tmpFile = (string)($state[$tmpKey] ?? '');
    $targetFile = (string)($state[$targetKey] ?? '');

    if ($tmpFile === '' || $targetFile === '') {
        throw new Exception('Web Worker backup dosya yolları eksik.');
    }

    if (!is_file($tmpFile) && $index === 0) {
        $gz = @gzopen($tmpFile, 'wb3');
        if (!$gz) throw new Exception('Web Worker geçici gzip dosyası oluşturulamadı.');
        safe_gzwrite($gz, "-- VEDO MYSQL BACKUP [WEB WORKER FALLBACK]\n-- DB: {$state['db_name']}\n-- TIME: " . date('Y-m-d H:i:s') . "\n-- NOTE: Shared hosting fallback; tablo bazlı HTTP worker kullanıldı.\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n\n");
        @gzclose($gz);
    }

    /*
     * WEB WORKER HIZ OPTİMİZASYONU:
     * Her HTTP isteğinde tek tablo yerine en fazla 4 tablo işlenir.
     * Böylece shared hosting ortamında HTTP istek sayısı azalır ve toplam yedekleme süresi kısalır.
     * Güvenlik için tek adım yaklaşık 6 saniyeyi aşarsa sonraki tablolar bir sonraki isteğe bırakılır.
     */
    if ($index < count($tables)) {
        $batchStartedAt = microtime(true);
        $processedBeforeBatch = $processedRows;
        $maxTablesPerStep = 4;
        $maxStepSeconds = 6.0;
        $tablesProcessed = 0;
        $gz = @gzopen($tmpFile, 'ab3');
        if (!$gz) throw new Exception('Web Worker geçici gzip dosyası açılamadı.');

        try {
            while ($index < count($tables) && $tablesProcessed < $maxTablesPerStep) {
                if ($tablesProcessed > 0 && (microtime(true) - $batchStartedAt) >= $maxStepSeconds) {
                    break;
                }

                $table = $tables[$index];
                export_single_table_to_stream(
                    $pdo,
                    $table,
                    $gz,
                    $state['db_name'],
                    $processedRows,
                    null,
                    (int)$config['max_insert_rows']
                );

                $index++;
                $tablesProcessed++;

                $state['status'] = 'running';
                $state['phase'] = 'backup';
                $state['current_table'] = $table;
                $state['current_table_index'] = $index;
                $state['total_tables'] = count($tables);
                $state['processed_rows'] = $processedRows;
                $state[$indexKey] = $index;
                $state[$rowsKey] = $processedRows;
            }
        } finally {
            @gzclose($gz);
        }

        $elapsedBatch = max(0.001, microtime(true) - $batchStartedAt);
        $jobStartedAt = (float)($state['job_started_at'] ?? microtime(true));
        $totalTables = count($tables);
        $elapsedTotal = max(0.001, microtime(true) - $jobStartedAt);
        $percent = $totalTables > 0
            ? min(99, (int)floor(($index / $totalTables) * 100))
            : 0;
        $speedRows = (int)round($processedRows / $elapsedTotal);
        $etaSeconds = 0;
        if ($percent > 0 && $percent < 100) {
            $etaSeconds = (int)round(($elapsedTotal / $percent) * (100 - $percent));
        }

        $state['status'] = 'running';
        $state['phase'] = 'backup';
        $state['percent'] = $percent;
        $state['total_tables'] = $totalTables;
        $state['current_table_index'] = $index;
        $state['processed_rows'] = $processedRows;
        $state['elapsed_seconds'] = round($elapsedTotal, 2);
        $state['estimated_remaining_seconds'] = $etaSeconds;
        $state['speed_rows_per_second'] = $speedRows;
        $state['speed_mb_per_second'] = round(((is_file($tmpFile) ? (int)filesize($tmpFile) : 0) / 1048576) / $elapsedTotal, 2);
        $state['bytes_written'] = is_file($tmpFile) ? (int)filesize($tmpFile) : 0;
        $state['formatted_bytes'] = format_bytes($state['bytes_written']);
        $state['tables_processed_this_step'] = $tablesProcessed;
        $state['message'] = sprintf('%d tablo işlendi, Web Worker devam ediyor.', $tablesProcessed);
        write_cli_job_state($backup_dir, $job_id, $state);
        return $state;
    }

    // Tablolar bitti: VIEW/TRIGGER/PROCEDURE/FUNCTION/EVENT nesnelerini ekle.
    if (empty($state['objects_exported'])) {
        $gz = @gzopen($tmpFile, 'ab3');
        if (!$gz) throw new Exception('Web Worker nesne export gzip dosyası açılamadı.');
        try {
            export_database_objects_to_stream($pdo, $state['db_name'], $gz);
            safe_gzwrite($gz, "\nSET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n");
        } finally {
            @gzclose($gz);
        }
        $state['objects_exported'] = true;
    }

    if (!@rename($tmpFile, $targetFile)) {
        throw new Exception('Web Worker geçici gzip dosyası hedef dosyaya taşınamadı.');
    }

    $hash = verify_and_checksum_gzip($targetFile);
    $size = is_file($targetFile) ? (int)filesize($targetFile) : 0;
    limit_backup_files($backup_dir, (int)$config['max_backups']);
    $duration = round(microtime(true) - (float)($state['job_started_at'] ?? microtime(true)), 2);

    $state['status'] = 'completed';
    $state['phase'] = 'completed';
    $state['percent'] = 100;
    $state['file'] = basename($targetFile);
    $state['size'] = $size;
    $state['bytes_written'] = $size;
    $state['formatted_bytes'] = format_bytes($size);
    $state['duration_seconds'] = $duration;
    $state['sha256'] = $hash;
    $state['current_table_index'] = count($tables);
    $state['total_tables'] = count($tables);
    $state['processed_rows'] = $processedRows;
    write_cli_job_state($backup_dir, $job_id, $state);

    Logger::info(sprintf(
        'WEB BACKUP BAŞARILI | job_id=%s | file=%s | tables=%d | rows=%d | size=%s | duration=%ss | sha256=%s',
        $job_id,
        basename($targetFile),
        count($tables),
        $processedRows,
        format_bytes($size),
        $duration,
        $hash
    ));
    return $state;
}
function initialize_web_backup_job(PDO $pdo, string $backup_dir, array $config, string $job_id): array {
    assert_no_active_database_job($backup_dir, $job_id);
    check_sufficient_disk_space($pdo, $config['db_name'], $backup_dir);
    $tables = get_web_worker_tables($pdo, $config['db_name']);
    $paths = build_web_backup_paths($backup_dir, $config['db_name']);
    $now = microtime(true);

    $state = [
        'job_id' => $job_id,
        'engine' => 'web',
        'type' => 'backup',
        'status' => 'starting',
        'phase' => 'backup',
        'db_name' => $config['db_name'],
        'tables' => $tables,
        'total_tables' => count($tables),
        'current_table_index' => 0,
        'processed_rows' => 0,
        'current_table' => '',
        'backup_table_index' => 0,
        'backup_processed_rows' => 0,
        'backup_tables' => $tables,
        'backup_tmp_file' => $paths['tmp'],
        'backup_target_file' => $paths['target'],
        'tmp_file' => $paths['tmp'],
        'target_file' => $paths['target'],
        'job_started_at' => $now,
        'message' => 'Shared hosting Web Worker başlatıldı.',
        'fallback_reason' => (string)($config['_web_fallback_reason'] ?? '')
    ];
    write_cli_job_state($backup_dir, $job_id, $state);

    Logger::warning(sprintf(
        'WEB WORKER FALLBACK | type=backup | job_id=%s | reason=%s',
        $job_id,
        $state['fallback_reason'] !== '' ? $state['fallback_reason'] : 'CLI kullanılamıyor.'
    ));
    return $state;
}
// Web Worker restore işini parça parça yürütür; önce veritabanı durumunu kontrol eder ve gerekiyorsa temizler.
function web_restore_step(PDO $pdo, string $job_id, string $backup_dir, array $config): array {
    $state = read_cli_job_state($backup_dir, $job_id);
    if (!$state || ($state['engine'] ?? '') !== 'web' || ($state['type'] ?? '') !== 'restore') {
        throw new Exception('Web Worker restore durumu bulunamadı.');
    }

    $file = (string)($state['file'] ?? '');
    if (!validate_backup_filename($file)) throw new Exception('Geçersiz Web Worker restore dosyası.');
    $safePath = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
    if (!is_file($safePath)) throw new Exception('Restore dosyası bulunamadı.');

    $phase = (string)($state['phase'] ?? 'verify_source');

    // WEB RESTORE KAYNAK DOĞRULAMASI
    // SHA-256 doğrulama durumu polling istekleri arasında korunur.
    if ($phase === 'check_database') {
        $phase = 'verify_source';
        $state['phase'] = 'verify_source';
    }

    if ($phase === 'verify_source') {
        $fileSize = (int)filesize($safePath);
        $verifyOffset = (int)($state['verify_offset'] ?? 0);
        $verifyCtxEncoded = (string)($state['verify_hash_context'] ?? '');

        if ($verifyOffset < 0 || $verifyOffset > $fileSize) {
            throw new Exception('Restore kaynak doğrulama konumu geçersiz.');
        }

        if ($verifyCtxEncoded !== '') {
            try {
                $hashCtx = unserialize(base64_decode($verifyCtxEncoded, true), ['allowed_classes' => true]);
                if (!$hashCtx instanceof HashContext) {
                    throw new Exception('SHA256 doğrulama state tipi geçersiz.');
                }
            } catch (Throwable $e) {
                throw new Exception('SHA256 doğrulama state okunamadı: ' . $e->getMessage(), 0, $e);
            }
        } else {
            $hashCtx = hash_init('sha256');
        }

        $fp = @fopen($safePath, 'rb');
        if (!$fp) throw new Exception('Restore dosyası doğrulama için açılamadı.');

        $stepStartedAt = microtime(true);
        $maxStepSeconds = 4.0;
        $chunkBytes = 1024 * 1024; // 1 MB
        $chunks = 0;
        try {
            if ($verifyOffset > 0 && fseek($fp, $verifyOffset, SEEK_SET) !== 0) {
                throw new Exception('Restore doğrulama dosya konumuna gidilemedi.');
            }

            while ($verifyOffset < $fileSize && (microtime(true) - $stepStartedAt) < $maxStepSeconds) {
                $readLen = min($chunkBytes, $fileSize - $verifyOffset);
                $chunk = fread($fp, $readLen);
                if ($chunk === false) {
                    throw new Exception('Restore dosyası checksum doğrulaması sırasında okunamadı.');
                }
                if ($chunk === '') {
                    throw new Exception('Restore dosyası checksum doğrulaması sırasında beklenmeyen EOF oluştu.');
                }

                hash_update($hashCtx, $chunk);
                $verifyOffset += strlen($chunk);
                $chunks++;
            }
        } finally {
            fclose($fp);
        }

        $state['verify_offset'] = $verifyOffset;
        $state['verify_file_size'] = $fileSize;
        $state['verify_hash_context'] = base64_encode(serialize($hashCtx));
        $state['status'] = 'running';
        $state['phase'] = 'verify_source';
        $state['current_table'] = 'Restore kaynağı doğrulanıyor';
        $state['percent'] = $fileSize > 0 ? min(99, (int)floor(($verifyOffset / $fileSize) * 100)) : 99;
        $state['message'] = sprintf(
            'Restore kaynağı doğrulanıyor... %s / %s',
            format_bytes($verifyOffset),
            format_bytes($fileSize)
        );

        if ($verifyOffset >= $fileSize) {
            $currentHash = strtolower(hash_final($hashCtx));
            $shaFile = $safePath . '.sha256';
            if (!is_file($shaFile)) {
                throw new Exception('Checksum (.sha256) dosyası bulunamadı.');
            }
            $shaContent = trim((string)@file_get_contents($shaFile));
            $parts = preg_split('/\s+/', $shaContent);
            $expectedHash = strtolower((string)($parts[0] ?? ''));
            if (!preg_match('/^[a-f0-9]{64}$/', $expectedHash)) {
                throw new Exception('Geçersiz checksum dosyası biçimi.');
            }
            if (!hash_equals($expectedHash, $currentHash)) {
                throw new Exception('Checksum uyuşmazlığı! Restore kaynağı değiştirilmiş veya bozulmuş.');
            }

            // Gzip başlığı ve akışı açılabiliyor mu diye doğrula. Restore motorunun
            // kendisi dosyanın tamamını okuyacağı için stream bütünlüğü de restore
            // sırasında kesin olarak kontrol edilir; burada en azından kaynağın
            // geçerli bir gzip olarak açılabildiğini restore öncesinde teyit ederiz.
            $gzTest = @gzopen($safePath, 'rb');
            if (!$gzTest) {
                throw new Exception('Restore kaynağı geçerli bir gzip arşivi olarak açılamadı.');
            }
            $probe = @gzread($gzTest, 65536);
            @gzclose($gzTest);
            if ($probe === false) {
                throw new Exception('Restore kaynağı gzip akışı okunamadı.');
            }

            unset($hashCtx);
            $state['verify_offset'] = $fileSize;
            $state['verify_hash_context'] = '';
            $state['backup_sha256'] = $currentHash;
            $state['source_verified'] = true;
            $state['source_gzip_verified'] = true;
            $state['phase'] = 'clear_database';
            $state['status'] = 'clearing';
            $state['percent'] = 0;
            $state['current_table'] = 'Veritabanına format atılıyor';
            $state['message'] = 'Restore kaynağı doğrulandı. Mevcut veritabanı tamamen temizlenecek.';

            Logger::info(sprintf(
                'WEB RESTORE KAYNAK DOĞRULANDI | job_id=%s | file=%s | sha256=%s | bytes=%d',
                $job_id,
                $file,
                $currentHash,
                $fileSize
            ));
        }

        write_cli_job_state($backup_dir, $job_id, $state);
        return $state;
    }

    // RESTORE ÖNCESİ DB FORMATLAMA
    if ($phase === 'clear_database') {
        if (empty($state['source_verified']) || empty($state['backup_sha256'])) {
            throw new Exception('Restore kaynağı doğrulanmadan veritabanı temizlenemez.');
        }

        $state['status'] = 'clearing';
        $state['message'] = 'Veritabanı tamamen temizleniyor...';
        $state['current_table'] = 'Veritabanına format atılıyor';
        $state['percent'] = 0;
        write_cli_job_state($backup_dir, $job_id, $state);

        $clearReport = clear_database_for_restore($pdo, $config['db_name']);
        $failedCount = count($clearReport['failed'] ?? []);
        if ($failedCount > 0) {
            $firstFailure = $clearReport['failed'][0] ?? [];
            throw new Exception(
                'Veritabanı temizlenemedi. Nesne: ' . (string)($firstFailure['object'] ?? '-') .
                ' | Tür: ' . (string)($firstFailure['type'] ?? '-') .
                ' | Hata: ' . (string)($firstFailure['reason'] ?? 'Bilinmeyen hata')
            );
        }

        $emptyReport = verify_database_is_empty_for_restore($pdo, $config['db_name']);

        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        $pdo->exec('SET UNIQUE_CHECKS=0');

        $state['phase'] = 'restore';
        $state['status'] = 'running';
        $state['processed_bytes'] = 0;
        $state['file_size'] = (int)filesize($safePath);
        $state['query_buffer'] = '';
        $state['in_string'] = false;
        $state['string_char'] = '';
        $state['in_comment_multi'] = false;
        $state['in_comment_single'] = false;
        $state['escaped'] = false;
        $state['current_delimiter'] = ';';
        $state['delimiter_line_buffer'] = '';
        $state['tables_count'] = 0;
        $state['rows_count'] = 0;
        $state['cleanup_verified'] = true;
        $state['cleanup_counts'] = $emptyReport;
        $state['message'] = 'Veritabanı formatlandı ve tamamen boş olduğu doğrulandı. Restore başlıyor.';
        $state['current_table'] = 'Restore başlatılıyor';
        write_cli_job_state($backup_dir, $job_id, $state);
        Logger::warning(sprintf(
            'WEB RESTORE DB FORMATLANDI | job_id=%s | file=%s | silinen_nesne=%d | tables=%d | triggers=%d | routines=%d | events=%d',
            $job_id,
            $file,
            count($clearReport['dropped'] ?? []),
            $emptyReport['tables'],
            $emptyReport['triggers'],
            $emptyReport['routines'],
            $emptyReport['events']
        ));
        return $state;
    }

    if ($phase !== 'restore') return $state;

    if (empty($state['cleanup_verified']) || !isset($state['cleanup_counts'])) {
        throw new Exception('Veritabanı temizliği doğrulanmadan restore devam ettirilemez.');
    }

    $fileSize = (int)($state['file_size'] ?? filesize($safePath));
    $processedBytes = (int)($state['processed_bytes'] ?? 0);
    $startedAt = (float)($state['job_started_at'] ?? microtime(true));

    $gz = @gzopen($safePath, 'rb');
    if (!$gz) throw new Exception('Web Worker restore gzip dosyası açılamadı.');
    try {
        if ($processedBytes > 0) {
            $seekResult = @gzseek($gz, $processedBytes, SEEK_SET);
            if ($seekResult < 0) {
                throw new Exception('Web Worker restore gzip konumuna gidilemedi.');
            }
        }

        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        $pdo->exec('SET UNIQUE_CHECKS=0');

        $queryBuffer = (string)($state['query_buffer'] ?? '');
        $inString = (bool)($state['in_string'] ?? false);
        $stringChar = (string)($state['string_char'] ?? '');
        $inCommentMulti = (bool)($state['in_comment_multi'] ?? false);
        $inCommentSingle = (bool)($state['in_comment_single'] ?? false);
        $escaped = (bool)($state['escaped'] ?? false);
        $currentDelimiter = (string)($state['current_delimiter'] ?? ';');
        $delimiterLineBuffer = (string)($state['delimiter_line_buffer'] ?? '');
        $tablesCount = (int)($state['tables_count'] ?? 0);
        $rowsCount = (int)($state['rows_count'] ?? 0);
        $currentRestoreTable = (string)($state['current_table'] ?? '');

        $stepStartedAt = microtime(true);
        $maxChunksPerStep = 8;
        $maxStepSeconds = 5.0;
        $chunksRead = 0;
        $eof = false;

        while ($chunksRead < $maxChunksPerStep && (microtime(true) - $stepStartedAt) < $maxStepSeconds) {
            $rawChunk = gzread($gz, VEDO_RESTORE_CHUNK_BYTES);
            if ($rawChunk === false) {
                throw new Exception('Web Worker restore verisi okunamadı.');
            }
            if ($rawChunk === '') {
                $eof = gzeof($gz);
                if ($eof) break;
                continue;
            }

            $chunksRead++;
            $processedBytes += strlen($rawChunk);
            $queries = restore_parse_buffer(
                $rawChunk,
                $queryBuffer,
                $inString,
                $stringChar,
                $inCommentMulti,
                $inCommentSingle,
                $escaped,
                $currentDelimiter,
                $delimiterLineBuffer
            );
            if ($queries) {
                restore_execute_sql($pdo, $queries, $tablesCount, $rowsCount, $backup_dir, $config, $currentRestoreTable);
            }

            $eof = gzeof($gz);
            if ($eof) break;
        }

        $state['processed_bytes'] = $processedBytes;
        $state['file_size'] = $fileSize;
        $state['query_buffer'] = $queryBuffer;
        $state['in_string'] = $inString;
        $state['string_char'] = $stringChar;
        $state['in_comment_multi'] = $inCommentMulti;
        $state['in_comment_single'] = $inCommentSingle;
        $state['escaped'] = $escaped;
        $state['current_delimiter'] = $currentDelimiter;
        $state['delimiter_line_buffer'] = $delimiterLineBuffer;
        $state['tables_count'] = $tablesCount;
        $state['rows_count'] = $rowsCount;
        $state['current_table'] = $currentRestoreTable !== '' ? $currentRestoreTable : 'Restore çalışıyor';
        $state['speed_mb_per_second'] = round(($processedBytes / 1048576) / max(0.1, microtime(true) - $startedAt), 2);

        if ($eof) {
            $finalQuery = finalize_restore_parser(
                $queryBuffer,
                $inString,
                $stringChar,
                $inCommentMulti,
                $inCommentSingle,
                $escaped,
                $currentDelimiter,
                $delimiterLineBuffer
            );
            if ($finalQuery !== null) {
                restore_execute_sql($pdo, [$finalQuery], $tablesCount, $rowsCount, $backup_dir, $config, $currentRestoreTable);
                $state['tables_count'] = $tablesCount;
                $state['rows_count'] = $rowsCount;
            }

            $pdo->exec('SET UNIQUE_CHECKS=1');
            $pdo->exec('SET FOREIGN_KEY_CHECKS=1');

            $integrity = $config['verify_after_restore']
                ? verify_database_integrity_after_restore($pdo, $config['db_name'], true, (bool)$config['analyze_after_restore'])
                : ['status' => 'SKIPPED', 'tables_checked' => 0, 'fk_issues' => 0, 'errors' => []];

            if (($integrity['status'] ?? '') === 'FAILED' || !empty($integrity['errors'])) {
                throw new Exception('Restore sonrası bütünlük kontrolü başarısız.');
            }

            $duration = round(microtime(true) - $startedAt, 2);
            $state['status'] = 'completed';
            $state['phase'] = 'completed';
            $state['percent'] = 100;
            $state['processed_bytes'] = $fileSize;
            $state['file_size'] = $fileSize;
            $state['duration_seconds'] = $duration;
            $state['backup_sha256'] = (string)($state['backup_sha256'] ?? '');
            $state['integrity'] = $integrity;
            $state['message'] = 'Restore başarıyla tamamlandı.';
            $state['current_table'] = $currentRestoreTable !== '' ? $currentRestoreTable : 'Restore tamamlandı';
            Logger::info(sprintf(
                'WEB RESTORE BAŞARILI | job_id=%s | file=%s | tables=%d | rows=%d | duration=%ss | integrity=%s',
                $job_id,
                $file,
                $tablesCount,
                $rowsCount,
                $duration,
                (string)($integrity['status'] ?? 'UNKNOWN')
            ));
        } else {
            $state['status'] = 'running';
            $state['phase'] = 'restore';
            $state['percent'] = $fileSize > 0 ? min(99, (int)floor(($processedBytes / $fileSize) * 100)) : 0;
            $state['message'] = $chunksRead > 0
                ? sprintf('Restore devam ediyor... (%d chunk)', $chunksRead)
                : 'Restore devam ediyor...';
        }

        write_cli_job_state($backup_dir, $job_id, $state);
    } finally {
        @gzclose($gz);
    }

    return $state;
}

function initialize_web_restore_job(PDO $pdo, string $backup_dir, array $config, string $job_id, string $file): array {
    assert_no_active_database_job($backup_dir, $job_id);
    if (!validate_backup_filename($file)) throw new Exception('Geçersiz restore dosyası.');
    $safePath = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
    if (!is_file($safePath)) throw new Exception('Restore dosyası bulunamadı.');

    $state = [
        'job_id' => $job_id,
        'engine' => 'web',
        'type' => 'restore',
        'status' => 'starting',
        'phase' => 'verify_source',
        'file' => $file,
        'file_size' => (int)filesize($safePath),
        'job_started_at' => microtime(true),
        'message' => 'Restore kaynağı doğrulanacak, ardından veritabanı tamamen temizlenecek.',
        'fallback_reason' => (string)($config['_web_fallback_reason'] ?? 'CLI kullanılamıyor.'),
        'source_verified' => false,
        'cleanup_verified' => false
    ];
    write_cli_job_state($backup_dir, $job_id, $state);
    Logger::warning(sprintf(
        'WEB WORKER RESTORE BAŞLATILDI | job_id=%s | file=%s | reason=%s',
        $job_id,
        $file,
        $state['fallback_reason']
    ));
    return $state;
}
function run_web_worker_step(PDO $pdo, string $backup_dir, array $config, string $job_id): array {
    $state = read_cli_job_state($backup_dir, $job_id);
    if (!$state || ($state['engine'] ?? '') !== 'web') {
        return $state;
    }

    $state['step_started_at'] = microtime(true);

    // Kaynak doğrulaması yalnızca dosya I/O + SHA256 işlemidir; database_operation
    // kilidine ihtiyaç duymaz. Böylece uzun checksum doğrulaması başka bir Web
    // Worker polling isteğini veya gerçek DB işlemini kilitlemez.
    $phase = (string)($state['phase'] ?? '');
    $is_restore_verification = (($state['type'] ?? '') === 'restore' && in_array($phase, ['verify_source', 'verifying'], true));

    if ($is_restore_verification) {
        return web_restore_step($pdo, $job_id, $backup_dir, $config);
    }

    $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, (int)$config['lock_timeout']);
    if (!$lock_handle) {
        // Başka bir DB işlemi devam ederken Web Worker'ı FAILED yapma.
        // Bir sonraki polling isteğinde kaldığı fazdan devam edecektir.
        $state['status'] = 'waiting';
        $state['message'] = 'Başka bir veritabanı işlemi aktif; Web Worker devam etmek için bekliyor.';
        $state['current_table'] = 'Veritabanı işlemi bekleniyor';
        write_cli_job_state($backup_dir, $job_id, $state);
        return $state;
    }

    try {
        update_system_lock_heartbeat($lock_handle);

        if (($state['type'] ?? '') === 'backup') {
            return web_backup_step($pdo, $job_id, $backup_dir, $config);
        }
        if (($state['type'] ?? '') === 'restore') {
            return web_restore_step($pdo, $job_id, $backup_dir, $config);
        }

        throw new Exception('Bilinmeyen Web Worker iş tipi.');
    } finally {
        release_system_lock($lock_handle);
    }
}
function perform_restore_cli_job(
    PDO $pdo,
    string $file,
    string $backup_dir,
    array $config,
    $lock_handle,
    string $job_id
): void {
    $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
    if (!is_file($safe_path) || !validate_backup_filename($file)) {
        throw new Exception('Geçersiz veya bulunamayan restore dosyası.');
    }

    $file_size = (int)filesize($safe_path);
    $processed_bytes = 0;
    $tables_count = 0;
    $rows_count = 0;
    $started_at = microtime(true);

    write_cli_job_state($backup_dir, $job_id, [
        'type' => 'restore',
        'status' => 'starting',
        'percent' => 0,
        'file' => $file,
        'tables_count' => 0,
        'rows_count' => 0,
        'source_verified' => false,
        'cleanup_verified' => false
    ]);

    try {
        $backup_sha256 = verify_restore_source_integrity($safe_path);
        Logger::info(sprintf('CLI RESTORE KAYNAK DOĞRULANDI | file=%s | sha256=%s', $file, $backup_sha256));

        $clearReport = clear_database_for_restore($pdo, $config['db_name']);
        $emptyReport = verify_database_is_empty_for_restore($pdo, $config['db_name']);
        Logger::warning(sprintf(
            'CLI RESTORE DB FORMATLANDI | file=%s | silinen_nesne=%d | tables=%d | triggers=%d | routines=%d | events=%d',
            $file,
            count($clearReport['dropped'] ?? []),
            $emptyReport['tables'],
            $emptyReport['triggers'],
            $emptyReport['routines'],
            $emptyReport['events']
        ));

        $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
        $pdo->exec('SET UNIQUE_CHECKS=0');

        $gz = gzopen($safe_path, 'rb');
        if (!$gz) throw new Exception('Gzip restore dosyası açılamadı.');

        $query_buffer = '';
        $in_string = false;
        $string_char = '';
        $in_comment_multi = false;
        $in_comment_single = false;
        $escaped = false;
        $current_delimiter = ';';
        $delimiter_line_buffer = '';
        $current_restore_table = '';

        try {
            write_cli_job_state($backup_dir, $job_id, [
                'type' => 'restore',
                'status' => 'running',
                'phase' => 'restore',
                'percent' => 0,
                'file' => $file,
                'tables_count' => 0,
                'rows_count' => 0
            ]);

            while (!gzeof($gz)) {
                $raw_chunk = gzread($gz, VEDO_RESTORE_CHUNK_BYTES);
                if ($raw_chunk === false || $raw_chunk === '') break;

                $read_len = strlen($raw_chunk);
                $processed_bytes += $read_len;

                $queries = restore_parse_buffer(
                    $raw_chunk,
                    $query_buffer,
                    $in_string,
                    $string_char,
                    $in_comment_multi,
                    $in_comment_single,
                    $escaped,
                    $current_delimiter
                );

                if ($queries) {
                    restore_execute_sql($pdo, $queries, $tables_count, $rows_count, $backup_dir, $config, $current_restore_table);
                }

                if (($processed_bytes % (16 * 1024 * 1024)) < $read_len) {
                    $pct = $file_size > 0 ? min(99, (int)floor(($processed_bytes / $file_size) * 100)) : 0;
                    write_cli_job_state($backup_dir, $job_id, [
                        'type' => 'restore',
                        'status' => 'running',
                        'phase' => 'restore',
                        'percent' => $pct,
                        'file' => $file,
                        'tables_count' => $tables_count,
                        'rows_count' => $rows_count,
                        'current_table' => $current_restore_table,
                        'processed_bytes' => $processed_bytes,
                        'file_size' => $file_size,
                        'formatted_processed' => format_bytes($processed_bytes),
                        'formatted_total' => format_bytes($file_size),
                        'speed_mb_per_second' => round(($processed_bytes / 1048576) / max(0.1, microtime(true) - $started_at), 2)
                    ]);
                }

                update_system_lock_heartbeat($lock_handle);
            }

            $final_query = finalize_restore_parser($query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer);
            if ($final_query !== null) {
                restore_execute_sql($pdo, [$final_query], $tables_count, $rows_count, $backup_dir, $config, $current_restore_table);
            }

            $pdo->exec('SET UNIQUE_CHECKS=1');
            $pdo->exec('SET FOREIGN_KEY_CHECKS=1');

            $integrity = $config['verify_after_restore']
                ? verify_database_integrity_after_restore($pdo, $config['db_name'], true, (bool)$config['analyze_after_restore'])
                : ['status' => 'SKIPPED', 'tables_checked' => 0, 'fk_issues' => 0, 'errors' => []];

            if (($integrity['status'] ?? '') === 'FAILED' || !empty($integrity['errors'])) {
                throw new Exception('Restore sonrası bütünlük kontrolü başarısız.');
            }

            @gzclose($gz);
            $gz = null;

            $restore_duration = round(microtime(true) - $started_at, 2);
            write_cli_job_state($backup_dir, $job_id, [
                'type' => 'restore',
                'status' => 'completed',
                'phase' => 'restore',
                'percent' => 100,
                'file' => $file,
                'tables_count' => $tables_count,
                'rows_count' => $rows_count,
                'current_table' => $current_restore_table !== '' ? $current_restore_table : 'Restore tamamlandı',
                'processed_bytes' => $file_size,
                'file_size' => $file_size,
                'duration_seconds' => $restore_duration,
                'backup_sha256' => $backup_sha256,
                'integrity' => $integrity
            ]);

            Logger::info(sprintf(
                'RESTORE BAŞARILI | file=%s | tables=%d | rows=%d | duration=%ss | integrity=%s',
                $file,
                $tables_count,
                $rows_count,
                $restore_duration,
                (string)($integrity['status'] ?? 'UNKNOWN')
            ));
        } finally {
            if (is_resource($gz)) @gzclose($gz);
        }
    } catch (Throwable $e) {
        try {
            $pdo->exec('SET UNIQUE_CHECKS=1');
            $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
        } catch (Throwable $ignored) {}

        $restore_duration = round(microtime(true) - $started_at, 2);
        write_cli_job_state($backup_dir, $job_id, [
            'type' => 'restore',
            'status' => 'failed',
            'percent' => min(99, $file_size > 0 ? (int)floor(($processed_bytes / $file_size) * 100) : 0),
            'file' => $file,
            'tables_count' => $tables_count,
            'rows_count' => $rows_count,
            'error' => $e->getMessage(),
            'duration_seconds' => $restore_duration
        ]);

        Logger::error(sprintf(
            'RESTORE BAŞARISIZ | file=%s | status=failed | tables=%d | rows=%d | rollback=YOK | duration=%ss | error=%s',
            $file,
            $tables_count,
            $rows_count,
            $restore_duration,
            $e->getMessage()
        ));

        throw $e;
    }
}
function resolve_cli_php_binary(): string {
    $candidates = [];

    // Web SAPI'da PHP_BINARY çoğu sunucuda php-fpm/cgi binary'sini gösterebilir.
    // Arka plan işini mutlaka gerçek CLI PHP ile başlat.
    if (PHP_OS_FAMILY === 'Windows') {
        if (defined('PHP_BINDIR')) {
            $candidates[] = rtrim(PHP_BINDIR, "\\/") . DIRECTORY_SEPARATOR . 'php.exe';
        }
        $candidates[] = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'php.exe';
        $candidates[] = 'php.exe';
    } else {
        if (defined('PHP_BINDIR')) {
            $candidates[] = rtrim(PHP_BINDIR, '/') . '/php';
        }
        $candidates[] = '/usr/bin/php';
        $candidates[] = '/usr/local/bin/php';

        $binary = (string)PHP_BINARY;
        if ($binary !== '' && is_executable($binary) &&
            !preg_match('/php(?:-fpm|-cgi)(?:\d+(?:\.\d+)*)?$/i', basename($binary))) {
            $candidates[] = $binary;
        }
        $candidates[] = 'php';
    }

    foreach (array_unique($candidates) as $candidate) {
        if ($candidate === 'php' || $candidate === 'php.exe') {
            return $candidate;
        }
        if (is_file($candidate) && is_executable($candidate)) {
            return $candidate;
        }
    }

    throw new Exception('Gerçek CLI PHP binary bulunamadı. PHP CLI kurulumunu kontrol edin.');
}
// GÜVENLİK: Log dosyasına gerçek cron tokenı yazılmaz; yalnızca komut yapısı kaydedilir.
function mask_cli_token_in_command(string $command, string $token): string {
    if ($token === '') return $command;
    return str_replace($token, '***CRON_TOKEN_MASKED***', $command);
}
function spawn_cli_job(string $script, string $token, string $job_type, string $job_id, string $file = ''): bool {
    if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) return false;
    if (!in_array($job_type, ['backup', 'restore'], true)) return false;

    try {
        $php = resolve_cli_php_binary();
    } catch (Throwable $e) {
        Logger::error('CLI process başlatılamadı: ' . $e->getMessage());
        return false;
    }

    $args = [
        escapeshellarg($php),
        escapeshellarg($script),
        escapeshellarg($token),
        escapeshellarg('--job=' . $job_type),
        escapeshellarg('--job-id=' . $job_id)
    ];
    if ($file !== '') {
        $args[] = escapeshellarg('--file=' . $file);
    }

    if (PHP_OS_FAMILY === 'Windows') {
        $cmd = 'start "" /B ' . implode(' ', $args) . ' > NUL 2>&1';
    } else {
        $cmd = 'nohup ' . implode(' ', $args) . ' > /dev/null 2>&1 < /dev/null &';
    }

    Logger::info(sprintf(
        'CLI KOMUTU | type=%s | job_id=%s | command=%s',
        $job_type,
        $job_id,
        mask_cli_token_in_command($cmd, $token)
    ));

    // exec() varsa doğrudan shell arka planı kullan.
    if (function_exists('exec')) {
        $output = [];
        $exitCode = 1;
        @exec($cmd, $output, $exitCode);
        if ($exitCode === 0) {
            Logger::info("CLI {$job_type} job başlatıldı: {$job_id}");
            return true;
        }
    }

    // exec() devre dışıysa proc_open() yedek yöntem olarak kullanılır.
    if (function_exists('proc_open')) {
        $descriptor = [
            0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'],
            1 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'a'],
            2 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'a'],
        ];
        $process = @proc_open($cmd, $descriptor, $pipes);
        if (is_resource($process)) {
            $exitCode = @proc_close($process);
            if ($exitCode === 0) {
                Logger::info("CLI {$job_type} job başlatıldı (proc_open): {$job_id}");
                return true;
            }
            Logger::error("CLI {$job_type} job proc_open ile başlatıldı ancak süreç 0 olmayan çıkış kodu verdi: {$job_id} [exit={$exitCode}]");
        }
    }

    Logger::error("CLI {$job_type} job başlatılamadı. exec/proc_open veya CLI PHP kontrol edilmeli: {$job_id}");
    return false;
}
function run_cli_job_from_argv(array $argv, array $config, string $backup_dir): void {
    $job_type = '';
    $job_id = '';
    $file = '';

    foreach ($argv as $arg) {
        if (str_starts_with((string)$arg, '--job=')) $job_type = substr((string)$arg, 6);
        elseif (str_starts_with((string)$arg, '--job-id=')) $job_id = substr((string)$arg, 9);
        elseif (str_starts_with((string)$arg, '--file=')) $file = substr((string)$arg, 7);
    }

    if (!in_array($job_type, ['backup', 'restore'], true) || !preg_match('/^[a-f0-9]{32}$/', $job_id)) {
        fwrite(STDERR, "ERROR: Geçersiz arka plan CLI işi.\n");
        exit(1);
    }

    clear_buffers();
    @set_time_limit(0);

    if (PHP_SAPI !== 'cli') {
        Logger::error('CLI İŞİ BAŞARISIZ | SAPI=cli değil | job=' . $job_type . ' | job_id=' . $job_id);
        fwrite(STDERR, "ERROR: Arka plan işi CLI SAPI dışında çalıştırılamaz.\n");
        exit(1);
    }

    Logger::info(sprintf(
        'CLI İŞİ ÇALIŞTI | type=%s | job_id=%s | file=%s | argv=%s',
        $job_type,
        $job_id,
        $file !== '' ? $file : '-',
        mask_cli_token_in_command(implode(' ', array_map('strval', $argv)), $config['cron_token'])
    ));

    if ($job_type === 'backup') {
        $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $config['lock_timeout']);
        if (!$lock_handle) {
            $lockError = 'Başka bir veritabanı işlemi aktif veya ortak işlem kilidi alınamadı.';
            write_cli_job_state($backup_dir, $job_id, [
                'type' => 'backup',
                'status' => 'failed',
                'percent' => 0,
                'error' => $lockError
            ]);
            Logger::error('CLI BACKUP BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $lockError);
            exit(1);
        }
        try {
            $job_started_at = microtime(true);
            write_cli_job_state($backup_dir, $job_id, [
                'type' => 'backup',
                'status' => 'starting',
                'percent' => 0,
                'message' => 'CLI PHP process başlatıldı.',
                'job_started_at' => $job_started_at
            ]);

            $pdo = get_pdo(
                $config['db_host'],
                $config['db_user'],
                $config['db_pass'],
                $config['db_name'],
                false,
                $config['use_persistent_pdo']
            );

            $progress_callback = static function (array $state) use ($backup_dir, $job_id): void {
                $state['type'] = 'backup';
                write_cli_job_state($backup_dir, $job_id, $state);
            };

            Logger::info('CLI BACKUP İŞLEMİ BAŞLADI | job_id=' . $job_id . ' | db=' . $config['db_name']);

            $file_path = perform_backup(
                $pdo,
                $config['db_name'],
                $backup_dir,
                $config,
                $lock_handle,
                $progress_callback
            );
            $size = is_file($file_path) ? filesize($file_path) : 0;
            $completed_at = microtime(true);
            $final_state = read_cli_job_state($backup_dir, $job_id);
            $duration = (int)round(
                $completed_at - (float)($final_state['job_started_at'] ?? $completed_at)
            );

            write_cli_job_state($backup_dir, $job_id, [
                'type' => 'backup',
                'status' => 'completed',
                'percent' => 100,
                'file' => basename($file_path),
                'size' => $size,
                'duration_seconds' => max(0, $duration),
                'current_table' => $final_state['current_table'] ?? '',
                'current_table_index' => (int)($final_state['total_tables'] ?? 0),
                'total_tables' => (int)($final_state['total_tables'] ?? 0),
                'processed_rows' => (int)($final_state['processed_rows'] ?? 0),
                'elapsed_seconds' => $duration,
                'estimated_remaining_seconds' => 0,
                'speed_rows_per_second' => (int)($final_state['speed_rows_per_second'] ?? 0),
                'speed_mb_per_second' => (float)($final_state['speed_mb_per_second'] ?? 0),
                'bytes_written' => (int)($final_state['bytes_written'] ?? $size),
                'formatted_bytes' => format_bytes($size),
                'updated_at' => date('Y-m-d H:i:s'),
                'job_started_at' => $final_state['job_started_at'] ?? $completed_at
            ]);

            Logger::info(sprintf(
                'CLI BACKUP BAŞARILI | job_id=%s | file=%s | size=%s | rows=%d | duration=%ss',
                $job_id,
                basename($file_path),
                format_bytes($size),
                (int)($final_state['processed_rows'] ?? 0),
                max(0, $duration)
            ));
        } catch (Throwable $e) {
            write_cli_job_state($backup_dir, $job_id, ['type'=>'backup','status'=>'failed','percent'=>0,'error'=>$e->getMessage()]);
            Logger::error(
                'CLI BACKUP BAŞARISIZ | job_id=' . $job_id .
                ' | hata=' . $e->getMessage()
            );
            exit(1);
        } finally {
            release_system_lock($lock_handle);
        }
        exit(0);
    }

    if (!is_string($file) || !validate_backup_filename($file)) {
        $error = 'Geçersiz restore dosyası.';
        write_cli_job_state($backup_dir, $job_id, ['type'=>'restore','status'=>'failed','percent'=>0,'error'=>$error]);
        Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $error);
        exit(1);
    }

    $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $config['lock_timeout']);
    if (!$lock_handle) {
        $error = 'Başka bir veritabanı işlemi aktif veya ortak işlem kilidi alınamadı.';
        write_cli_job_state($backup_dir, $job_id, ['type'=>'restore','status'=>'failed','percent'=>0,'error'=>$error]);
        Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $error);
        exit(1);
    }

    $restoreCliStart = microtime(true);
    Logger::info('CLI RESTORE İŞLEMİ BAŞLADI | job_id=' . $job_id . ' | file=' . $file . ' | db=' . $config['db_name']);

    try {
        $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
        perform_restore_cli_job($pdo, $file, $backup_dir, $config, $lock_handle, $job_id);
        Logger::info(sprintf('CLI RESTORE İŞLEMİ TAMAMLANDI | job_id=%s | file=%s | duration=%ss', $job_id, $file, round(microtime(true)-$restoreCliStart,2)));
    } catch (Throwable $e) {
        Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | file=' . $file . ' | duration=' . round(microtime(true)-$restoreCliStart,2) . 's | hata=' . $e->getMessage());
        exit(1);
    } finally {
        release_system_lock($lock_handle);
    }
    exit(0);
}

$is_cli_sapi = (php_sapi_name() === 'cli');
$has_cron_token = false;

if ($is_cli_sapi && isset($argv) && is_array($argv)) {
    foreach ($argv as $arg) {
        if (hash_equals($config['cron_token'], (string)$arg)) {
            $has_cron_token = true;
            break;
        }
    }
}

$is_cli_cron = ($is_cli_sapi && $has_cron_token);

if ($is_cli_cron && isset($argv) && is_array($argv)) {
    $has_background_job = false;
    foreach ($argv as $arg) {
        if (str_starts_with((string)$arg, '--job=')) {
            $has_background_job = true;
            break;
        }
    }
    if ($has_background_job) {
        run_cli_job_from_argv($argv, $config, $backup_dir);
    }
}

if ($is_cli_cron) {
    clear_buffers();
    @set_time_limit(0);

    $cronInvocation = implode(' ', array_map('strval', $argv ?? []));
    Logger::info('CRON KOMUTU ÇALIŞTI | command=' . mask_cli_token_in_command($cronInvocation, $config['cron_token']));
    Logger::info('CRON BACKUP İŞLEMİ BAŞLADI | db=' . $config['db_name']);

    $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $config['lock_timeout']);
    if (!$lock_handle) {
        Logger::error('CRON BACKUP BAŞARISIZ | hata=Backup kilidi alınamadı veya başka bir işlem aktif.');
        fwrite(STDERR, "ERROR: Islem zaten aktif veya kilit alinamadi.\n");
        exit(1);
    }

    $pdo = null;

    try {
        $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
        $cronStart = microtime(true);
        $cronFile = perform_backup($pdo, $config['db_name'], $backup_dir, $config, $lock_handle);
        $cronDuration = round(microtime(true) - $cronStart, 2);
        $cronSize = is_file($cronFile) ? filesize($cronFile) : 0;
        Logger::info(sprintf('CRON BACKUP SUCCESS | file=%s | size=%s | duration=%ss', basename($cronFile), format_bytes($cronSize), $cronDuration));
        echo "SUCCESS | " . basename($cronFile) . " | " . format_bytes($cronSize) . " | " . $cronDuration . "s\n";
        exit(0);
    } catch (Exception $e) {
        Logger::error("CRON BACKUP FAILED | " . get_class($e) . ' - ' . $e->getMessage());
        safe_transaction_rollback($pdo);
        fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
        exit(1);
    } finally {
        release_system_lock($lock_handle);
    }
}

if (php_sapi_name() === 'cli') {
    fwrite(STDERR, "ERROR: Gecerli cron token verilmedi.\n");
    exit(1);
}

/**
 * Persistan login rate-limit durumu. Session'a bağlı olmadığı için yeni session
 * açarak limitin aşılması engellenir. Sadece başarısız denemeleri kısa süre tutar.
 */
// Rate-limit dosya anahtarı için kullanıcı adı ve IP SHA-256 ile özetlenir.
function get_login_rate_limit_keys(string $ip, string $username): array {
    $ip = substr($ip, 0, 128);
    $username = strtolower(trim($username));

    return [
        'combo' => hash('sha256', $ip . "\0" . $username),
        'ip'    => hash('sha256', "ip\0" . $ip),
        'user'  => hash('sha256', "user\0" . $username),
    ];
}
function read_login_rate_limit(string $backup_dir, string $key): array {
    $path = $backup_dir . '/.login_rate_' . $key . '.json';
    $empty = ['failures' => 0, 'first_failure' => 0, 'locked_until' => 0];

    if (!is_file($path)) {
        return $empty;
    }

    $raw = @file_get_contents($path);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($data)) {
        return $empty;
    }

    return [
        'failures'      => max(0, (int)($data['failures'] ?? 0)),
        'first_failure' => max(0, (int)($data['first_failure'] ?? 0)),
        'locked_until'  => max(0, (int)($data['locked_until'] ?? 0)),
    ];
}
function write_login_rate_limit(string $backup_dir, string $key, array $state): void {
    $path = $backup_dir . '/.login_rate_' . $key . '.json';
    $tmp = $path . '.tmp';
    $json = json_encode([
        'failures'      => max(0, (int)($state['failures'] ?? 0)),
        'first_failure' => max(0, (int)($state['first_failure'] ?? 0)),
        'locked_until'  => max(0, (int)($state['locked_until'] ?? 0)),
        'updated_at'    => time(),
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

    if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
        @unlink($tmp);
        Logger::warning('Login rate-limit durumu yazılamadı.');
    }
}
function clear_login_rate_limit(string $backup_dir, string $key): void {
    $path = $backup_dir . '/.login_rate_' . $key . '.json';
    if (is_file($path)) {
        @unlink($path);
    }
}
function clear_login_rate_limit_all(string $backup_dir, string $ip, string $username): void {
    foreach (get_login_rate_limit_keys($ip, $username) as $key) {
        clear_login_rate_limit($backup_dir, $key);
    }
}
function enforce_login_rate_limit(string $backup_dir, string $ip, string $username, array $config): array {
    $keys = get_login_rate_limit_keys($ip, $username);
    $now = time();
    $window = max(300, (int)($config['rate_limit_window'] ?? $config['lockout_time'] ?? 900));
    $remaining = 0;
    $lockedBy = [];

    foreach ($keys as $type => $key) {
        $state = read_login_rate_limit($backup_dir, $key);

        // Sayaç penceresi dolmuşsa eski kayıt sıfırlanır.
        if ($state['first_failure'] > 0 && ($now - $state['first_failure']) > $window) {
            clear_login_rate_limit($backup_dir, $key);
            $state = ['failures' => 0, 'first_failure' => 0, 'locked_until' => 0];
        }

        if ($state['locked_until'] > $now) {
            $remaining = max($remaining, $state['locked_until'] - $now);
            $lockedBy[] = $type;
        }
    }

    return [
        'locked'    => $remaining > 0,
        'remaining' => $remaining,
        'keys'      => $keys,
        'locked_by' => $lockedBy,
    ];
}
function register_login_failure_all(string $backup_dir, string $ip, string $username, array $config): array {
    $keys = get_login_rate_limit_keys($ip, $username);
    $limits = [
        'combo' => max(1, (int)($config['max_login_attempts'] ?? 5)),
        'ip'    => max(1, (int)($config['max_ip_attempts'] ?? 20)),
        'user'  => max(1, (int)($config['max_user_attempts'] ?? 10)),
    ];
    $now = time();
    $window = max(300, (int)($config['rate_limit_window'] ?? $config['lockout_time'] ?? 900));
    $maxState = ['failures' => 0, 'locked_until' => 0];

    foreach ($keys as $type => $key) {
        $lockPath = $backup_dir . '/.login_rate_' . $key . '.lock';
        $lockFp = @fopen($lockPath, 'c+');
        if (!$lockFp || !@flock($lockFp, LOCK_EX)) {
            if (is_resource($lockFp)) @fclose($lockFp);
            Logger::warning('Login rate-limit kilidi alınamadı; güvenli varsayılan uygulanıyor.');
            $state = ['failures' => $limits[$type], 'first_failure' => $now, 'locked_until' => $now + $window];
            $maxState['failures'] = max($maxState['failures'], $state['failures']);
            $maxState['locked_until'] = max($maxState['locked_until'], $state['locked_until']);
            continue;
        }

        try {
            $state = read_login_rate_limit($backup_dir, $key);
            if ($state['first_failure'] <= 0 || ($now - $state['first_failure']) > $window) {
                $state = ['failures' => 0, 'first_failure' => $now, 'locked_until' => 0];
            }

            $state['failures']++;
            if ($state['failures'] >= $limits[$type]) {
                $state['locked_until'] = $now + $window;
            }

            write_login_rate_limit($backup_dir, $key, $state);
            $maxState['failures'] = max($maxState['failures'], $state['failures']);
            $maxState['locked_until'] = max($maxState['locked_until'], $state['locked_until']);
        } finally {
            @flock($lockFp, LOCK_UN);
            @fclose($lockFp);
        }
    }

    return $maxState;
}

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'secure'   => !empty($_SERVER['HTTPS']),
    'samesite' => 'Strict'
]);
session_start();

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_POST['logout']) && (string)$_POST['logout'] === '1') {
    $logout_csrf = (string)($_POST['csrf_token'] ?? '');
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $logout_csrf)) { http_response_code(403); exit('CSRF doğrulaması başarısız.'); }
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $params['path'],
            'domain'   => $params['domain'],
            'secure'   => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Strict',
        ]);
    }
    session_destroy();
    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

$login_ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN');
$login_username = isset($_POST['username']) ? (string)$_POST['username'] : '';
$rate_limit = enforce_login_rate_limit($backup_dir, $login_ip, $login_username, $config);
$is_locked = $rate_limit['locked'];
$remaining_time = $rate_limit['remaining'];

if (isset($_POST['username'], $_POST['password'])) {
    $login_csrf = (string)($_POST['csrf_token'] ?? '');
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $login_csrf)) {
        Logger::warning("Geçersiz CSRF giriş denemesi. IP: {$login_ip}");
        $err = "Geçersiz CSRF Token!";
    } elseif ($is_locked) {
        $err = "Çok fazla hatalı giriş! Lütfen {$remaining_time} saniye sonra tekrar deneyin.";
    } else {
        $user_captcha = (int)($_POST['captcha'] ?? 0);
        $correct_captcha = (int)($_SESSION['captcha_ans'] ?? -1);
        if ($user_captcha !== $correct_captcha) {
            $state = register_login_failure_all($backup_dir, $login_ip, $login_username, $config);
            Logger::warning("Hatalı Captcha girişi. IP: {$login_ip}");
            if (($state['locked_until'] ?? 0) > time()) {
                $is_locked = true;
                $remaining_time = $state['locked_until'] - time();
            }
            $err = "Güvenlik sorusu yanıtı hatalı!";
        } elseif (
            hash_equals($config['auth_user'], (string)$_POST['username']) &&
            hash_equals($config['auth_pass'], (string)$_POST['password'])
        ) {
            $_SESSION['logged_in'] = true;
            unset($_SESSION['captcha_ans']);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            session_regenerate_id(true);
            clear_login_rate_limit_all($backup_dir, $login_ip, $login_username);
            Logger::info("Başarılı kullanıcı girişi yapıldı.");
            header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
            exit;
        } else {
            $state = register_login_failure_all($backup_dir, $login_ip, $login_username, $config);
            Logger::warning("Başarısız giriş denemesi. IP: {$login_ip}");
            if (($state['locked_until'] ?? 0) > time()) {
                $is_locked = true;
                $remaining_time = $state['locked_until'] - time();
                $err = "Çok fazla hatalı giriş! Hesap 15 dakika kilitlendi.";
            } else {
                $err = "Hatalı kullanıcı adı veya şifre!";
            }
        }
    }
}

if (empty($_SESSION['logged_in'])) {
    $num1 = random_int(1, 9);
    $num2 = random_int(1, 9);
    $_SESSION['captcha_ans'] = $num1 + $num2;
    clear_buffers();
    ?>
    <!DOCTYPE html>
    <html lang="tr">
    <head>

        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Giriş - VEDO MySQL Panel</title>
        <style>
            :root { --vedo-ui-font: <?= htmlspecialchars($config['ui_font'], ENT_QUOTES, 'UTF-8') ?>; color-scheme: dark; --login-bg:#121212; --login-card:#1e1e1e; --login-border:#333; --login-text:#fff; --login-muted:#aaa; --login-input:#2a2a2a; --login-input-border:#444; --login-error-bg:#5a1a1a; --login-error-text:#ff8888; --login-error-border:#882222; --login-shadow:0 4px 20px rgba(0,0,0,.5); }
            html.theme-dark { color-scheme: dark; --login-bg:#121212; --login-card:#1e1e1e; --login-border:#333; --login-text:#fff; --login-muted:#aaa; --login-input:#2a2a2a; --login-input-border:#444; --login-error-bg:#5a1a1a; --login-error-text:#ff8888; --login-error-border:#882222; --login-shadow:0 4px 20px rgba(0,0,0,.5); }
            html.theme-light { color-scheme: light; --login-bg:#f5f7fa; --login-card:#fff; --login-border:#dbe2ea; --login-text:#1c2733; --login-muted:#667585; --login-input:#fff; --login-input-border:#cbd5df; --login-error-bg:#fff1f1; --login-error-text:#b42318; --login-error-border:#f3b4b0; --login-shadow:0 12px 36px rgba(32,56,85,.12); }
            body { background:var(--login-bg); color:var(--login-text); font-family: var(--vedo-ui-font) !important; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; padding:20px; box-sizing:border-box; transition:background-color .2s ease,color .2s ease; }
            .login-wrap { width:100%; max-width:400px; }
            .login-toolbar { display:flex; justify-content:flex-end; margin-bottom:10px; }
            .login-theme-toggle { width:auto; margin:0; padding:8px 12px; background:transparent; color:var(--login-text); border:1px solid var(--login-border); border-radius:6px; cursor:pointer; }
            .login-theme-toggle:hover { background:rgba(127,127,127,.10); }
            .login-card { background:var(--login-card); border-radius:12px; padding:30px; width:100%; box-sizing:border-box; box-shadow:var(--login-shadow); border:1px solid var(--login-border); }
            h2 { margin-top:0; color:var(--login-text); text-align:center; }
            .form-group { margin-bottom:15px; }
            label { display:block; margin-bottom:5px; color:var(--login-muted); font-size:14px; }
            input[type="text"],input[type="password"],input[type="number"] { width:100%; padding:10px; border-radius:6px; border:1px solid var(--login-input-border); background:var(--login-input); color:var(--login-text); box-sizing:border-box; }
            .login-submit { width:100%; padding:10px; border:none; border-radius:6px; background:#007bff; color:#fff; font-weight: 500; cursor:pointer; margin-top:10px; }
            .login-submit:hover { background:#0056b3; }
            .error { background:var(--login-error-bg); color:var(--login-error-text); padding:10px; border-radius:6px; font-size:13px; margin-bottom:15px; border:1px solid var(--login-error-border); }

/* ÇALIŞMA MODU: CLI veya WEB seçimini üst menüde gösterir. Sayfa açılışında CLI seçilidir. */
.worker-mode-control{display:inline-flex;align-items:center;transform:translateY(4px);gap:7px;padding:5px 8px;border:1px solid var(--border);border-radius:8px;background:var(--card-bg);color:var(--text);font-weight: 500;}
.worker-mode-control label{white-space:nowrap;color:var(--text-secondary);}
.worker-mode-control select{border:1px solid var(--border);border-radius:6px;background:var(--input-bg);color:var(--text);font:inherit;font-weight: 500;padding:4px 7px;cursor:pointer;}
.worker-mode-control span{white-space:nowrap;color:var(--text-secondary);}
</style>
</head>
    <body>
        <div class="login-wrap">
            <div class="login-toolbar"><button type="button" class="login-theme-toggle" id="loginThemeToggle">☾ Koyu Tema</button></div>
            <div class="login-card">
            <h2>VEDO Panel Girişi</h2>
            <?php if (!empty($err)): ?>
                <div class="error"><?= htmlspecialchars($err) ?></div>
            <?php endif; ?>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <div class="form-group">
                    <label>Kullanıcı Adı</label>
                    <input type="text" name="username" required autofocus autocomplete="off">
                </div>
                <div class="form-group">
                    <label>Şifre</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>Güvenlik Sorusu: <?= $num1 ?> + <?= $num2 ?> = ?</label>
                    <input type="number" name="captcha" required autocomplete="off">
                </div>
                <button type="submit" class="login-submit">Giriş Yap</button>
            </form>
            </div>
        </div>
        <script nonce="<?= $nonce ?>">
            (()=>{const key='vedo_theme',saved=localStorage.getItem(key),defaultTheme='<?= $config['ui_default_theme'] === 'light' ? 'light' : 'dark' ?>',theme=saved==='light'||saved==='dark'?saved:defaultTheme;document.documentElement.classList.toggle('theme-dark',theme==='dark');document.documentElement.classList.toggle('theme-light',theme==='light');const btn=document.getElementById('loginThemeToggle');const update=()=>{const dark=document.documentElement.classList.contains('theme-dark');btn.textContent=dark?'☀ Açık Tema':'☾ Koyu Tema';};update();btn?.addEventListener('click',()=>{const dark=!document.documentElement.classList.contains('theme-dark');document.documentElement.classList.toggle('theme-dark',dark);document.documentElement.classList.toggle('theme-light',!dark);localStorage.setItem(key,dark?'dark':'light');update();});})();
        </script>
    </body>
    </html>
    <?php
    exit;
}

/**
 * Linux /proc/stat üzerinden kısa örneklemeli gerçek CPU kullanımını ölçer.
 * sys_getloadavg() CPU yüzdesi değildir; load average yerine kernel CPU sayaç deltası kullanılır.
 * Sonuç 0-100 arası toplam CPU kullanımını temsil eder; 100 = tüm mantıksal çekirdekler dolu.
 */
function read_cpu_proc_stat(): ?array {
    if (!is_readable('/proc/stat')) {
        return null;
    }

    $content = @file_get_contents('/proc/stat');
    if ($content === false) {
        return null;
    }

    foreach (preg_split('/\R/', $content) as $line) {
        if (!preg_match('/^cpu\s+(\d+(?:\s+\d+){2,9})\s*$/', trim($line), $m)) {
            continue;
        }

        $fields = array_map('intval', preg_split('/\s+/', trim($m[1])));
        if (count($fields) < 4) {
            return null;
        }

        // /proc/stat: user nice system idle iowait irq softirq steal guest guest_nice
        $user = $fields[0] ?? 0;
        $nice = $fields[1] ?? 0;
        $system = $fields[2] ?? 0;
        $idle = $fields[3] ?? 0;
        $iowait = $fields[4] ?? 0;
        $irq = $fields[5] ?? 0;
        $softirq = $fields[6] ?? 0;
        $steal = $fields[7] ?? 0;
        $guest = $fields[8] ?? 0;
        $guestNice = $fields[9] ?? 0;

        $total = array_sum($fields);
        $busy = $user + $nice + $system + $irq + $softirq + $steal;
        $idleTotal = $idle + $iowait;

        return [
            'total' => $total,
            'busy' => $busy,
            'idle' => $idleTotal,
            'guest' => $guest,
            'guest_nice' => $guestNice,
            'timestamp' => microtime(true),
        ];
    }

    return null;
}

function get_cpu_core_count(): int {
    static $coreCount = null;
    if ($coreCount !== null) {
        return $coreCount;
    }

    if (is_readable('/sys/devices/system/cpu/online')) {
        $online = trim((string)@file_get_contents('/sys/devices/system/cpu/online'));
        if ($online !== '') {
            $count = 0;
            foreach (preg_split('/,/', $online) as $range) {
                $range = trim($range);
                if ($range === '') continue;
                if (str_contains($range, '-')) {
                    [$start, $end] = array_map('intval', explode('-', $range, 2));
                    if ($end >= $start) {
                        $count += ($end - $start + 1);
                    }
                } elseif (ctype_digit($range)) {
                    $count++;
                }
            }
            if ($count > 0) {
                return $coreCount = $count;
            }
        }
    }

    if (is_readable('/proc/cpuinfo')) {
        $cpuInfo = @file_get_contents('/proc/cpuinfo');
        if ($cpuInfo !== false) {
            $count = substr_count($cpuInfo, "\nprocessor\t:");
            if ($count > 0) {
                return $coreCount = $count;
            }
            $count = preg_match_all('/^processor\s*:/mi', $cpuInfo, $unused);
            if ($count > 0) {
                return $coreCount = $count;
            }
        }
    }

    return $coreCount = max(1, (int)(function_exists('shell_exec') ? @shell_exec('getconf _NPROCESSORS_ONLN 2>/dev/null') : 1));
}

function get_instant_cpu_metrics(int $sampleMs = 120): array {
    $cores = get_cpu_core_count();
    $load1 = 0.0;
    $load5 = 0.0;
    $load15 = 0.0;

    if (function_exists('sys_getloadavg')) {
        $loads = sys_getloadavg();
        if (is_array($loads)) {
            $load1 = round((float)($loads[0] ?? 0), 2);
            $load5 = round((float)($loads[1] ?? 0), 2);
            $load15 = round((float)($loads[2] ?? 0), 2);
        }
    }

    $first = read_cpu_proc_stat();
    if ($first !== null) {
        usleep(max(50000, min(500000, $sampleMs * 1000)));
        $second = read_cpu_proc_stat();

        if ($second !== null) {
            $totalDelta = $second['total'] - $first['total'];
            $busyDelta = $second['busy'] - $first['busy'];

            if ($totalDelta > 0 && $busyDelta >= 0) {
                $percent = ($busyDelta / $totalDelta) * 100;
                return [
                    'percent' => round(min(100, max(0, $percent)), 1),
                    'load_1min' => $load1,
                    'load_5min' => $load5,
                    'load_15min' => $load15,
                    'cores' => $cores,
                    'sample_ms' => $sampleMs,
                    'source' => '/proc/stat'
                ];
            }
        }
    }

    // /proc/stat yoksa (ör. bazı Windows/shared hosting ortamları) load average yalnızca geri dönüş yöntemidir.
    $fallback = $cores > 0 ? ($load1 / $cores) * 100 : 0;
    return [
        'percent' => round(min(100, max(0, $fallback)), 1),
        'load_1min' => $load1,
        'load_5min' => $load5,
        'load_15min' => $load15,
        'cores' => $cores,
        'sample_ms' => 0,
        'source' => 'loadavg-fallback'
    ];
}

function get_server_metrics(array $config, string $backup_dir): array {
    $metrics = [
        'hostname' => gethostname() ?: 'N/A',
        'os' => PHP_OS_FAMILY . ' (' . php_uname('r') . ')',
        'php_version' => PHP_VERSION,
        'php_sapi' => php_sapi_name(),
        'mysql_version' => 'N/A',
        'server_time' => date('Y-m-d H:i:s'),
        'uptime' => 'N/A',
        'cpu' => [
            'cores' => 1,
            'load_1min' => 0.0,
            'load_5min' => 0.0,
            'load_15min' => 0.0,
            'percent' => 0
        ],
        'ram' => [
            'total' => 0,
            'used' => 0,
            'free' => 0,
            'percent' => 0
        ],
        'disk' => [
            'total' => 0,
            'used' => 0,
            'free' => 0,
            'percent' => 0
        ],
        'backup_dir' => [
            'size' => 0,
            'formatted_size' => '0 B',
            'count' => 0
        ],
        'php_env' => [
            'memory_limit' => ini_get('memory_limit') ?: 'N/A',
            'max_execution_time' => ini_get('max_execution_time') . 's',
            'upload_max_filesize' => ini_get('upload_max_filesize') ?: 'N/A',
            'post_max_size' => ini_get('post_max_size') ?: 'N/A',
            'max_input_time' => ini_get('max_input_time') . 's',
            'max_input_vars' => ini_get('max_input_vars') ?: 'N/A',
            'display_errors' => ini_get('display_errors') ?: '0',
            'timezone' => date_default_timezone_get(),
            'zend_version' => zend_version(),
            'loaded_ini' => php_ini_loaded_file() ?: 'N/A',
            'extensions_count' => count(get_loaded_extensions())
        ],
        'php_extensions' => [],
        'mysql' => [
            'server_version' => 'N/A',
            'client_version' => defined('PDO::MYSQL_ATTR_SERVER_VERSION') ? 'N/A' : 'N/A',
            'connection_status' => 'N/A',
            'charset' => 'utf8mb4',
            'character_set_server' => 'N/A',
            'collation_server' => 'N/A',
            'max_connections' => 'N/A',
            'max_allowed_packet' => 'N/A',
            'innodb_buffer_pool_size' => 'N/A',
            'sql_mode' => 'N/A',
            'time_zone' => 'N/A'
        ],
        'server' => [
            'hostname' => gethostname() ?: 'N/A',
            'os' => PHP_OS_FAMILY,
            'kernel' => php_uname('r'),
            'machine' => php_uname('m'),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI/Unknown',
            'server_protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'N/A',
            'https' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'ON' : 'OFF',
            'server_ip' => $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname() ?: 'localhost'),
            'remote_ip' => $_SERVER['REMOTE_ADDR'] ?? 'N/A',
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? __DIR__,
            'script_path' => __FILE__,
            'timezone' => date_default_timezone_get(),
            'current_time' => date('Y-m-d H:i:s'),
            'memory_limit' => ini_get('memory_limit') ?: 'N/A',
            'disk_path' => $backup_dir
        ],
        'database' => [
            'name' => $config['db_name'],
            'host' => $config['db_host'],
            'user' => $config['db_user'],
            'table_count' => 0,
            'size' => 0,
            'formatted_size' => '0 B',
            'total_rows' => 0
        ]
    ];

    // CPU kullanımı kısa /proc/stat örneklemesiyle ölçülür.
    $cpu = get_instant_cpu_metrics(120);
    $metrics['cpu']['cores'] = (int)$cpu['cores'];
    $metrics['cpu']['load_1min'] = (float)$cpu['load_1min'];
    $metrics['cpu']['load_5min'] = (float)$cpu['load_5min'];
    $metrics['cpu']['load_15min'] = (float)$cpu['load_15min'];
    $metrics['cpu']['percent'] = (float)$cpu['percent'];

    // Çalışma süresi.
    if (is_readable('/proc/uptime')) {
        $uptime_str = file_get_contents('/proc/uptime');
        if ($uptime_str !== false) {
            $uptime_sec = (int)floatval(explode(' ', $uptime_str)[0]);
            $days = floor($uptime_sec / 86400);
            $hours = floor(($uptime_sec % 86400) / 3600);
            $mins = floor(($uptime_sec % 3600) / 60);
            $metrics['uptime'] = "{$days}g {$hours}s {$mins}dk";
        }
    }

    // Bellek (RAM).
    if (is_readable('/proc/meminfo')) {
        $meminfo = file_get_contents('/proc/meminfo');
        if ($meminfo !== false) {
            preg_match('/MemTotal:\s+(\d+)\s+kB/i', $meminfo, $m_tot);
            preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $meminfo, $m_avail);

            $tot_bytes = isset($m_tot[1]) ? (int)$m_tot[1] * 1024 : 0;
            $avail_bytes = isset($m_avail[1]) ? (int)$m_avail[1] * 1024 : 0;
            $used_bytes = max(0, $tot_bytes - $avail_bytes);

            if ($tot_bytes > 0) {
                $metrics['ram']['total'] = $tot_bytes;
                $metrics['ram']['used'] = $used_bytes;
                $metrics['ram']['free'] = $avail_bytes;
                $metrics['ram']['percent'] = round(($used_bytes / $tot_bytes) * 100);
            }
        }
    }

    // Disk.
    $disk_free = @disk_free_space($backup_dir);
    $disk_total = @disk_total_space($backup_dir);
    if ($disk_free !== false && $disk_total !== false && $disk_total > 0) {
        $disk_used = $disk_total - $disk_free;
        $metrics['disk']['total'] = $disk_total;
        $metrics['disk']['used'] = $disk_used;
        $metrics['disk']['free'] = $disk_free;
        $metrics['disk']['percent'] = round(($disk_used / $disk_total) * 100);
    }

    // Yedek klasörünü tek geçişte tarayarak boyut, adet ve son yedeği hesapla.
    $b_size = 0;
    $b_count = 0;
    $latestBackup = null;
    if (is_dir($backup_dir)) {
        try {
            foreach (new DirectoryIterator($backup_dir) as $fileinfo) {
                if (!$fileinfo->isFile() || !str_ends_with($fileinfo->getFilename(), '.sql.gz')) continue;

                $fileSize = $fileinfo->getSize();
                $fileTime = $fileinfo->getMTime();
                $b_size += $fileSize;
                $b_count++;

                if ($latestBackup === null || $fileTime > $latestBackup['time']) {
                    $latestBackup = [
                        'name' => $fileinfo->getFilename(),
                        'size' => $fileSize,
                        'formatted_size' => format_bytes($fileSize),
                        'time' => $fileTime,
                        'mtime' => date('Y-m-d H:i:s', $fileTime)
                    ];
                }
            }
        } catch (Exception $e) {
            Logger::warning('Yedek klasörü metrikleri okunamadı: ' . $e->getMessage());
        }
    }
    $metrics['backup_dir']['size'] = $b_size;
    $metrics['backup_dir']['formatted_size'] = format_bytes($b_size);
    $metrics['backup_dir']['count'] = $b_count;

    // Son başarılı yedeği yalnızca tamamlanmış .sql.gz dosyaları arasından bildir.
    if ($latestBackup !== null) {
        unset($latestBackup['time']);
    }
    $metrics['backup_dir']['last_successful'] = $latestBackup;

    // Database MySQL Version + summary
    try {
        $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
        $metrics['mysql_version'] = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) ?: 'N/A';
        $metrics['mysql']['server_version'] = $metrics['mysql_version'];
        try {
            $metrics['mysql']['client_version'] = defined('PDO::MYSQL_ATTR_CLIENT_VERSION')
                ? (string)$pdo->getAttribute(PDO::MYSQL_ATTR_CLIENT_VERSION)
                : 'N/A';
        } catch (Throwable $e) {
            $metrics['mysql']['client_version'] = 'N/A';
        }
        try {
            $metrics['mysql']['connection_status'] = (string)($pdo->getAttribute(PDO::ATTR_CONNECTION_STATUS) ?: 'Connected');
        } catch (Throwable $e) {
            $metrics['mysql']['connection_status'] = 'Connected';
        }
        try {
            $varsStmt = $pdo->query("SHOW VARIABLES WHERE Variable_name IN ('character_set_server','collation_server','max_connections','max_allowed_packet','innodb_buffer_pool_size','sql_mode','time_zone')");
            $mysqlVars = $varsStmt ? $varsStmt->fetchAll(PDO::FETCH_KEY_PAIR) : [];
            if ($varsStmt) $varsStmt->closeCursor();
            $metrics['mysql']['character_set_server'] = (string)($mysqlVars['character_set_server'] ?? 'N/A');
            $metrics['mysql']['collation_server'] = (string)($mysqlVars['collation_server'] ?? 'N/A');
            $metrics['mysql']['max_connections'] = (string)($mysqlVars['max_connections'] ?? 'N/A');
            $metrics['mysql']['max_allowed_packet'] = (string)($mysqlVars['max_allowed_packet'] ?? 'N/A');
            $metrics['mysql']['innodb_buffer_pool_size'] = isset($mysqlVars['innodb_buffer_pool_size'])
                ? format_bytes((int)$mysqlVars['innodb_buffer_pool_size'])
                : 'N/A';
            $metrics['mysql']['sql_mode'] = (string)($mysqlVars['sql_mode'] ?? 'N/A');
            $metrics['mysql']['time_zone'] = (string)($mysqlVars['time_zone'] ?? 'N/A');
        } catch (Throwable $e) {
            Logger::warning('MySQL ayrıntılı değişkenleri okunamadı: ' . $e->getMessage());
        }
        $metrics['php_extensions'] = get_loaded_extensions();
        sort($metrics['php_extensions'], SORT_NATURAL | SORT_FLAG_CASE);
        $dbStmt = $pdo->prepare("SELECT COUNT(*) AS table_count, COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH),0) AS db_size, COALESCE(SUM(TABLE_ROWS),0) AS total_rows FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?");
        $dbStmt->execute([$config['db_name']]);
        $dbRow = $dbStmt->fetch(PDO::FETCH_ASSOC) ?: [];
        $dbStmt->closeCursor();
        $metrics['database']['table_count'] = (int)($dbRow['table_count'] ?? 0);
        $metrics['database']['size'] = (int)($dbRow['db_size'] ?? 0);
        $metrics['database']['formatted_size'] = format_bytes($metrics['database']['size']);
        $metrics['database']['total_rows'] = (int)($dbRow['total_rows'] ?? 0);
    } catch (Exception $e) {}

    return $metrics;
}

// 9. VERİTABANI GEZGİNİ YARDIMCILARI
function validate_db_identifier(string $name): string {
    if (!preg_match('/^[A-Za-z0-9_$]+$/', $name)) {
        throw new Exception('Geçersiz veritabanı veya tablo adı.');
    }
    return $name;
}
function get_database_tables(PDO $pdo, string $db_name): array {
    $stmt = $pdo->prepare("SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, DATA_LENGTH, INDEX_LENGTH, CREATE_TIME, UPDATE_TIME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME ASC");
    $stmt->execute([$db_name]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $stmt->closeCursor();
    foreach ($rows as &$row) {
        $row['TABLE_ROWS'] = (int)($row['TABLE_ROWS'] ?? 0);
        $row['DATA_LENGTH'] = (int)($row['DATA_LENGTH'] ?? 0);
        $row['INDEX_LENGTH'] = (int)($row['INDEX_LENGTH'] ?? 0);
        $row['TOTAL_SIZE'] = $row['DATA_LENGTH'] + $row['INDEX_LENGTH'];
        $row['FORMATTED_SIZE'] = format_bytes($row['TOTAL_SIZE']);
    }
    unset($row);
    return $rows;
}
function get_table_structure(PDO $pdo, string $db_name, string $table): array {
    $table = validate_db_identifier($table);
    $stmt = $pdo->prepare("SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION");
    $stmt->execute([$db_name, $table]);
    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $stmt->closeCursor();
    return $columns;
}
function get_table_preview(PDO $pdo, string $db_name, string $table, int $limit = 100, int $offset = 0): array {
    $table = validate_db_identifier($table);
    $limit = max(1, min(100, $limit));
    $offset = max(0, $offset);
    $stmt = $pdo->query("SELECT * FROM `{$table}` LIMIT {$offset}, {$limit}");
    $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
    if ($stmt) $stmt->closeCursor();
    return ['rows' => $rows, 'offset' => $offset, 'limit' => $limit];
}
function perform_table_maintenance(PDO $pdo, string $db_name, string $table, string $operation): string {
    $table = validate_db_identifier($table);
    $allowed = ['analyze' => 'ANALYZE TABLE', 'repair' => 'REPAIR TABLE', 'optimize' => 'OPTIMIZE TABLE'];
    if (!isset($allowed[$operation])) throw new Exception('Geçersiz bakım işlemi.');
    $stmt = $pdo->query($allowed[$operation] . " `{$table}`");
    $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
    if ($stmt) $stmt->closeCursor();
    $messages = [];
    foreach ($rows as $row) {
        $messages[] = ($row['Msg_type'] ?? '') . ': ' . ($row['Msg_text'] ?? '');
    }
    Logger::info("Tablo bakımı: {$operation} / {$table}");
    return implode(' | ', $messages) ?: 'İşlem tamamlandı.';
}
function truncate_table(PDO $pdo, string $table): void {
    $table = validate_db_identifier($table);
    $pdo->exec("TRUNCATE TABLE `{$table}`");
    Logger::warning("Tablo boşaltıldı: {$table}");
}
function drop_table(PDO $pdo, string $table): void {
    $table = validate_db_identifier($table);
    $pdo->exec("DROP TABLE `{$table}`");
    Logger::warning("Tablo silindi: {$table}");
}

// 10. API İŞLEM YÖNLENDİRİCİSİ
$allowed_actions = [
    'run_full_backup',
    'restore_chunk',
    'delete_backup',
    'download_backup',
    'check_integrity',
    'get_dashboard_data',
    'live_metrics',
    'clear_logs',
    'get_cli_job_progress',
    'get_active_cli_jobs',
    'get_worker_capabilities',
    'db_tables',
    'db_table_data',
    'db_table_structure',
    'db_table_maintenance',
    'db_table_truncate',
    'db_table_drop',
    'bulk_delete_backups',
    'client_activity_log',
    'empty_database'
];

$action = $_REQUEST['action'] ?? '';

if (!empty($action)) {
    if (!in_array($action, $allowed_actions, true)) {
        json_response(false, 'Geçersiz işlem veya istek reddedildi.', [], 400);
    }

    if (empty($_SESSION['logged_in'])) {
        json_response(false, 'Yetkisiz erişim.', [], 401);
    }

    $request_csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_REQUEST['csrf_token'] ?? '';
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $request_csrf)) {
        json_response(false, 'Güvenlik Doğrulaması (CSRF) Başarısız!', [], 403);
    }

        // SADECE CPU/RAM/DISK: dashboard/log/SQL akışına dokunmaz.
        // Bu endpoint PDO bağlantısı kurmaz ve yalnızca sistem metriklerini döndürür.
        if ($action === 'live_metrics') {
            $cpuLive = get_instant_cpu_metrics(120);
            $cpuPercent = (float)$cpuLive['percent'];
            $cpuCores = (int)$cpuLive['cores'];
            $load1 = (float)$cpuLive['load_1min'];
            $load5 = (float)$cpuLive['load_5min'];
            $load15 = (float)$cpuLive['load_15min'];

            $ramTotal = 0;
            $ramAvailable = 0;
            if (is_readable('/proc/meminfo')) {
                $mem = @file_get_contents('/proc/meminfo');
                if ($mem !== false) {
                    if (preg_match('/MemTotal:\s+(\d+)\s+kB/i', $mem, $m)) {
                        $ramTotal = (int)$m[1] * 1024;
                    }
                    if (preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $mem, $m)) {
                        $ramAvailable = (int)$m[1] * 1024;
                    }
                }
            }
            $ramUsed = max(0, $ramTotal - $ramAvailable);
            $ramPercent = $ramTotal > 0 ? round(($ramUsed / $ramTotal) * 100, 1) : 0;

            $diskPath = $backup_dir;
            $diskFree = @disk_free_space($diskPath);
            $diskTotal = @disk_total_space($diskPath);
            $diskUsed = ($diskFree !== false && $diskTotal !== false && $diskTotal > 0)
                ? max(0, $diskTotal - $diskFree) : 0;
            $diskPercent = ($diskTotal !== false && $diskTotal > 0)
                ? round(($diskUsed / $diskTotal) * 100, 1) : 0;

            json_response(true, 'Canlı metrikler.', [
                'cpu' => [
                    'percent' => $cpuPercent,
                    'load_1min' => $load1,
                    'load_5min' => $load5,
                    'load_15min' => $load15,
                    'cores' => $cpuCores,
                    'sample_ms' => (int)$cpuLive['sample_ms'],
                    'source' => (string)$cpuLive['source']
                ],
                'ram' => [
                    'percent' => $ramPercent,
                    'used' => $ramUsed,
                    'total' => $ramTotal,
                    'free' => $ramAvailable
                ],
                'disk' => [
                    'percent' => $diskPercent,
                    'used' => $diskUsed,
                    'total' => $diskTotal,
                    'free' => $diskFree !== false ? $diskFree : 0
                ]
            ]);
        }

    try {
        $pdo = init_pdo_with_dynamic_memory($config);

        if ($action === 'db_tables') {
            json_response(true, 'Tablolar listelendi.', ['tables' => get_database_tables($pdo, $config['db_name']), 'database' => $config['db_name']]);
        }

        if ($action === 'db_table_structure') {
            $table = validate_db_identifier((string)($_POST['table'] ?? $_GET['table'] ?? ''));
            json_response(true, 'Tablo yapısı yüklendi.', ['table' => $table, 'columns' => get_table_structure($pdo, $config['db_name'], $table)]);
        }

        if ($action === 'db_table_data') {
            $table = validate_db_identifier((string)($_POST['table'] ?? $_GET['table'] ?? ''));
            $limit = (int)($_POST['limit'] ?? $_GET['limit'] ?? 50);
            $offset = (int)($_POST['offset'] ?? $_GET['offset'] ?? 0);
            $data = get_table_preview($pdo, $config['db_name'], $table, $limit, $offset);
            json_response(true, 'Tablo verileri yüklendi.', ['table' => $table] + $data);
        }

        if ($action === 'db_table_maintenance') {
            require_post();
            $table = validate_db_identifier((string)($_POST['table'] ?? ''));
            $operation = (string)($_POST['operation'] ?? '');
            $message = with_database_operation_lock($backup_dir, (int)$config['lock_timeout'], function () use ($pdo, $config, $table, $operation) {
                return perform_table_maintenance($pdo, $config['db_name'], $table, $operation);
            });
            json_response(true, strtoupper($operation) . ' tamamlandı.', ['message' => $message]);
        }

        if ($action === 'db_table_truncate') {
            require_post();
            $table = validate_db_identifier((string)($_POST['table'] ?? ''));
            with_database_operation_lock($backup_dir, (int)$config['lock_timeout'], function () use ($pdo, $table) {
                truncate_table($pdo, $table);
                return true;
            });
            json_response(true, "'{$table}' tablosu boşaltıldı.");
        }

        if ($action === 'db_table_drop') {
            require_post();
            $table = validate_db_identifier((string)($_POST['table'] ?? ''));
            with_database_operation_lock($backup_dir, (int)$config['lock_timeout'], function () use ($pdo, $table) {
                drop_table($pdo, $table);
                return true;
            });
            json_response(true, "'{$table}' tablosu silindi.");
        }

        if ($action === 'get_worker_capabilities') {
            require_post();
            $cli = detect_cli_worker_capability();
            json_response(true, 'Worker yetenekleri alındı.', [
                'cli_available' => (bool)$cli['available'],
                'cli_php' => $cli['php_binary'],
                'reason' => $cli['reason'],
                'web_fallback_available' => true
            ]);
        }

        // Varsayılan seçim CLI'dir; WEB seçilirse Web Worker zorunlu olarak kullanılır.
        if ($action === 'run_full_backup') {
            require_post();
            $worker_mode = strtolower(trim((string)($_POST['worker_mode'] ?? 'cli')));
            if (!in_array($worker_mode, ['cli', 'web'], true)) {
                json_response(false, 'Geçersiz çalışma modu. CLI veya WEB seçilmelidir.', [], 400);
            }

            $job_id = bin2hex(random_bytes(16));

            if ($worker_mode === 'cli') {
                $cli = detect_cli_worker_capability();
                if (!$cli['available']) {
                    Logger::error('CLI BACKUP BAŞLATILAMADI | kullanıcı modu=CLI | neden=' . ($cli['reason'] ?: 'CLI worker kullanılamıyor.'));
                    json_response(false, 'CLI worker bu sunucuda kullanılamıyor. Çalışma Modu bölümünden WEB seçerek devam edebilirsiniz.', [
                        'engine' => 'cli',
                        'cli_available' => false,
                        'reason' => $cli['reason']
                    ], 503);
                }
                if (spawn_cli_job(__FILE__, $config['cron_token'], 'backup', $job_id)) {
                    json_response(true, 'CLI backup arka planda başlatıldı.', [
                        'status' => 'starting',
                        'job_id' => $job_id,
                        'engine' => 'cli'
                    ]);
                }
                Logger::error('CLI BACKUP BAŞLATILAMADI | kullanıcı modu=CLI | job_id=' . $job_id);
                json_response(false, 'CLI backup süreci başlatılamadı. Çalışma Modu bölümünden WEB seçerek devam edebilirsiniz.', [
                    'engine' => 'cli',
                    'job_id' => $job_id
                ], 503);
            }

            $config['_web_fallback_reason'] = 'Kullanıcı WEB çalışma modunu seçti.';
            $state = initialize_web_backup_job($pdo, $backup_dir, $config, $job_id);
            json_response(true, 'Web Worker yedekleme başlatıldı.', [
                'status' => $state['status'],
                'job_id' => $job_id,
                'engine' => 'web',
                'message' => 'Web Worker ile yedekleme adım adım yürütülecek.'
            ]);
        }

        if ($action === 'get_active_cli_jobs') {
            require_post();
            cleanup_stale_cli_job_states($backup_dir);
            json_response(true, 'Aktif CLI işler alındı.', [
                'jobs' => find_active_cli_job_states($backup_dir)
            ]);
        }

        if ($action === 'get_cli_job_progress') {
            require_post();
            $job_id = (string)($_POST['job_id'] ?? '');
            if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
                json_response(false, 'Geçersiz CLI job ID.', [], 400);
            }
            $state = read_cli_job_state($backup_dir, $job_id);
            if (!$state) {
                json_response(true, 'Job henüz başlamadı.', ['status' => 'starting', 'percent' => 0, 'job_id' => $job_id]);
            }

            // Web Worker işlerinde her progress sorgusu aynı zamanda bir küçük işlem adımıdır.
            if (($state['engine'] ?? 'cli') === 'web' && in_array((string)($state['status'] ?? ''), ['starting', 'verifying', 'waiting', 'running', 'clearing', 'restoring'], true)) {
                try {
                    $state = run_web_worker_step($pdo, $backup_dir, $config, $job_id);
                } catch (Throwable $workerError) {
                    $state['status'] = 'failed';
                    $state['error'] = $workerError->getMessage();
                    write_cli_job_state($backup_dir, $job_id, $state);
                    Logger::error(sprintf('WEB WORKER BAŞARISIZ | job_id=%s | type=%s | rollback=YOK | error=%s', $job_id, $state['type'] ?? '-', $workerError->getMessage()));
                }
            }

            json_response(true, 'Job durumu alındı.', $state);
        }

        if ($action === 'get_dashboard_data') {
            $metrics = get_server_metrics($config, $backup_dir);

            // Yedek dosyaları listesi.
            $files = [];
            if (is_dir($backup_dir)) {
                try {
                    $iterator = new DirectoryIterator($backup_dir);
                    foreach ($iterator as $fileinfo) {
                        if ($fileinfo->isFile() && str_ends_with($fileinfo->getFilename(), '.sql.gz')) {
                            $filename = $fileinfo->getFilename();
                            $path = $fileinfo->getPathname();
                            $sha_file = $path . '.sha256';

                            $fileSize = $fileinfo->getSize();
                            $fileTime = $fileinfo->getMTime();
                            $files[] = [
                                'name' => $filename,
                                'size' => format_bytes($fileSize),
                                'bytes' => $fileSize,
                                'mtime' => date('Y-m-d H:i:s', $fileTime),
                                'has_sha256' => is_file($sha_file)
                            ];
                        }
                    }
                    usort($files, fn($a, $b) => strcmp($b['mtime'], $a['mtime']));
                } catch (Exception $e) {
                    Logger::warning('Yedek listesi okunamadı: ' . $e->getMessage());
                }
            }

            $logLines = read_last_file_lines($backup_dir . '/system.log', 200);

            json_response(true, 'Dashboard verileri yüklendi.', [
                'metrics' => $metrics,
                'files'   => $files,
                'logs'    => $logLines
            ]);
        }

if ($action === 'client_activity_log') {
    require_post();
    if (!verify_csrf_token((string)($_POST['csrf_token'] ?? ''))) {
        json_response(false, 'CSRF doğrulaması başarısız.', [], 403);
    }

    $actionName = trim((string)($_POST['action_name'] ?? ''));
    $details = trim((string)($_POST['details'] ?? ''));

    // Aktivite adı kısa ve hassas veri içermemeli.
    if ($actionName === '' || !preg_match('/^[\p{L}\p{N}_ .:+\-\/()]+$/u', $actionName)) {
        json_response(false, 'Geçersiz aktivite adı.', [], 400);
    }

    $details = mb_substr($details, 0, 500);
    // Aktivite ayrıntılarındaki hassas değerleri loglamadan önce maskele.
    $details = preg_replace(
        '/(?:password|passwd|pass|token|secret|csrf|session[_-]?id|authorization|cookie)\s*[:=]\s*[^|,;\s]+/iu',
        '$0',
        $details
    ) ?? $details;
    $details = preg_replace(
        '/((?:password|passwd|pass|token|secret|csrf|session[_-]?id|authorization|cookie)\s*[:=]\s*)[^|,;\s]+/iu',
        '$1***REDACTED***',
        $details
    ) ?? $details;
    $details = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $details) ?? $details;
    Logger::info('Panel işlemi: ' . $actionName . ($details !== '' ? ' | ' . $details : ''));
    json_response(true, 'Aktivite loglandı.');
}

if ($action === 'bulk_delete_backups') {
    require_post();

    $token = (string)($_POST['csrf_token'] ?? '');
    if (!verify_csrf_token($token)) {
        json_response(false, 'CSRF doğrulaması başarısız.', [], 403);
    }

    $rawFiles = $_POST['files'] ?? [];
    if (is_string($rawFiles)) {
        $decoded = json_decode($rawFiles, true);
        $rawFiles = is_array($decoded) ? $decoded : [];
    }
    if (!is_array($rawFiles)) {
        json_response(false, 'Geçersiz yedek listesi.', [], 400);
    }

    $files = [];
    foreach ($rawFiles as $file) {
        $file = trim((string)$file);
        if ($file !== '' && validate_backup_filename($file)) {
            $files[$file] = true;
        }
    }
    if (!$files) {
        json_response(false, 'Silinecek yedek seçilmedi.', [], 400);
    }

    $deleted = [];
    $failed = [];

    foreach (array_keys($files) as $file) {
        try {
            $safePath = validate_path_safe($backup_dir . DIRECTORY_SEPARATOR . $file, $backup_dir);
            if (!is_file($safePath)) {
                $failed[] = ['file'=>$file, 'reason'=>'Dosya bulunamadı'];
                continue;
            }

            if (!@unlink($safePath)) {
                $failed[] = ['file'=>$file, 'reason'=>'Dosya silinemedi'];
                continue;
            }

            foreach ([
                $safePath . '.sha256',
            ] as $sidecar) {
                if (is_file($sidecar)) @unlink($sidecar);
            }

            $deleted[]=$file;
            Logger::info("Toplu yedek silindi: {$file}");
        } catch (Throwable $e) {
            $failed[]=['file'=>$file,'reason'=>$e->getMessage()];
            Logger::error("Toplu yedek silme hatası: {$file} - ".$e->getMessage());
        }
    }

    $deletedCount=count($deleted);
    $failedCount=count($failed);

    json_response(
        $deletedCount > 0,
        $failedCount > 0
            ? "{$deletedCount} yedek silindi, {$failedCount} yedek silinemedi."
            : "{$deletedCount} yedek başarıyla silindi.",
        [
            'deleted'=>$deletedCount,
            'deleted_files'=>$deleted,
            'failed'=>$failed
        ],
        $deletedCount > 0 ? 200 : 400
    );
}

if ($action === 'empty_database') {
    require_post();

    // Mevcut uygulama bağlantı ayarlarıyla PDO bağlantısı oluşturulur.
    $pdo = get_pdo(
        $config['db_host'],
        $config['db_user'],
        $config['db_pass'],
        $config['db_name'],
        false,
        $config['use_persistent_pdo']
    );

    $dbName = (string)$config['db_name'];
    $dropped = [];
    $failed = [];
    $emptyLock = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, (int)$config['lock_timeout']);
    if (!$emptyLock) {
        json_response(false, 'Başka bir veritabanı işlemi aktif. Yeni işlem başlatılamaz.', [], 409);
    }

    try {
        require_database_operation_lock($emptyLock, $backup_dir);
        update_system_lock_heartbeat($emptyLock);
        // Önce mevcut tablo ve view isimleri alınır.
        // Bu sorgu yalnızca hedef veritabanındaki nesneleri listeler.
        $stmt = $pdo->prepare("
            SELECT TABLE_NAME, TABLE_TYPE
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = ?
            ORDER BY TABLE_TYPE, TABLE_NAME
        ");
        $stmt->execute([$dbName]);
        $objects = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        // Foreign key ilişkileri DROP işlemini engellemesin.
        $pdo->exec("SET FOREIGN_KEY_CHECKS=0");

        // Önce tablolar ve view'lar kaldırılır.
        foreach ($objects as $object) {
            $name = (string)($object['TABLE_NAME'] ?? '');
            $type = strtoupper((string)($object['TABLE_TYPE'] ?? ''));

            // SQL identifier güvenliği: sadece gerçek MySQL isim karakterlerine izin ver.
            if ($name === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $name)) {
                $failed[] = [
                    'object' => $name,
                    'type' => $type,
                    'reason' => 'Güvenli olmayan nesne adı'
                ];
                continue;
            }

            $quotedName = '`' . str_replace('`', '``', $name) . '`';

            try {
                if ($type === 'VIEW') {
                    // View tamamen kaldırılır.
                    $pdo->exec("DROP VIEW IF EXISTS {$quotedName}");
                } else {
                    // BASE TABLE ve varsa diğer tablo tipleri tamamen kaldırılır.
                    $pdo->exec("DROP TABLE IF EXISTS {$quotedName}");
                }

                $dropped[] = [
                    'object' => $name,
                    'type' => $type
                ];
                Logger::info("Veritabanı nesnesi tamamen silindi: {$type} {$name}");
            } catch (Throwable $e) {
                $failed[] = [
                    'object' => $name,
                    'type' => $type,
                    'reason' => $e->getMessage()
                ];
                Logger::error(
                    "Veritabanı nesnesi silinemedi: {$type} {$name} - " .
                    $e->getMessage()
                );
            }
        }

        // Trigger'lar ayrı nesnedir; tablo silinse bile kalan trigger'ları da temizle.
        try {
            $stmt = $pdo->prepare("
                SELECT TRIGGER_NAME
                FROM information_schema.TRIGGERS
                WHERE TRIGGER_SCHEMA = ?
            ");
            $stmt->execute([$dbName]);
            $triggers = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $stmt->closeCursor();

            foreach ($triggers as $trigger) {
                $trigger = (string)$trigger;
                if ($trigger === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $trigger)) {
                    $failed[] = [
                        'object' => $trigger,
                        'type' => 'TRIGGER',
                        'reason' => 'Güvenli olmayan trigger adı'
                    ];
                    continue;
                }

                $quotedTrigger = '`' . str_replace('`', '``', $trigger) . '`';

                try {
                    $pdo->exec("DROP TRIGGER IF EXISTS {$quotedTrigger}");
                    $dropped[] = [
                        'object' => $trigger,
                        'type' => 'TRIGGER'
                    ];
                    Logger::info("Trigger tamamen silindi: {$trigger}");
                } catch (Throwable $e) {
                    $failed[] = [
                        'object' => $trigger,
                        'type' => 'TRIGGER',
                        'reason' => $e->getMessage()
                    ];
                    Logger::error(
                        "Trigger silinemedi: {$trigger} - " . $e->getMessage()
                    );
                }
            }
        } catch (Throwable $e) {
            // TRIGGER sorgusu yetki nedeniyle çalışmazsa ana işlem başarısız kabul edilir.
            $failed[] = [
                'object' => '*',
                'type' => 'TRIGGER',
                'reason' => $e->getMessage()
            ];
        }

        // Stored procedure ve function nesnelerini temizler.
        try {
            $stmt = $pdo->prepare("
                SELECT ROUTINE_NAME, ROUTINE_TYPE
                FROM information_schema.ROUTINES
                WHERE ROUTINE_SCHEMA = ?
            ");
            $stmt->execute([$dbName]);
            $routines = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $stmt->closeCursor();

            foreach ($routines as $routine) {
                $name = (string)($routine['ROUTINE_NAME'] ?? '');
                $type = strtoupper((string)($routine['ROUTINE_TYPE'] ?? ''));

                if ($name === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $name)) {
                    $failed[] = [
                        'object' => $name,
                        'type' => $type,
                        'reason' => 'Güvenli olmayan routine adı'
                    ];
                    continue;
                }

                $quotedName = '`' . str_replace('`', '``', $name) . '`';

                try {
                    if ($type === 'FUNCTION') {
                        $pdo->exec("DROP FUNCTION IF EXISTS {$quotedName}");
                    } else {
                        $pdo->exec("DROP PROCEDURE IF EXISTS {$quotedName}");
                    }

                    $dropped[] = [
                        'object' => $name,
                        'type' => $type
                    ];
                    Logger::info("Routine tamamen silindi: {$type} {$name}");
                } catch (Throwable $e) {
                    $failed[] = [
                        'object' => $name,
                        'type' => $type,
                        'reason' => $e->getMessage()
                    ];
                    Logger::error(
                        "Routine silinemedi: {$type} {$name} - " .
                        $e->getMessage()
                    );
                }
            }
        } catch (Throwable $e) {
            $failed[] = [
                'object' => '*',
                'type' => 'ROUTINE',
                'reason' => $e->getMessage()
            ];
        }

        // Event Scheduler nesnelerini de kaldır.
        try {
            $stmt = $pdo->prepare("
                SELECT EVENT_NAME
                FROM information_schema.EVENTS
                WHERE EVENT_SCHEMA = ?
            ");
            $stmt->execute([$dbName]);
            $events = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $stmt->closeCursor();

            foreach ($events as $event) {
                $event = (string)$event;

                if ($event === '' || !preg_match('/^[A-Za-z0-9_$]+$/', $event)) {
                    $failed[] = [
                        'object' => $event,
                        'type' => 'EVENT',
                        'reason' => 'Güvenli olmayan event adı'
                    ];
                    continue;
                }

                $quotedEvent = '`' . str_replace('`', '``', $event) . '`';

                try {
                    $pdo->exec("DROP EVENT IF EXISTS {$quotedEvent}");
                    $dropped[] = [
                        'object' => $event,
                        'type' => 'EVENT'
                    ];
                    Logger::info("Event tamamen silindi: {$event}");
                } catch (Throwable $e) {
                    $failed[] = [
                        'object' => $event,
                        'type' => 'EVENT',
                        'reason' => $e->getMessage()
                    ];
                    Logger::error(
                        "Event silinemedi: {$event} - " . $e->getMessage()
                    );
                }
            }
        } catch (Throwable $e) {
            $failed[] = [
                'object' => '*',
                'type' => 'EVENT',
                'reason' => $e->getMessage()
            ];
        }

        // Foreign key kontrollerini her durumda yeniden etkinleştir.
        try {
            $pdo->exec("SET FOREIGN_KEY_CHECKS=1");
        } catch (Throwable $ignored) {
            Logger::error("FOREIGN_KEY_CHECKS geri açılamadı.");
        }

        // Son güvenlik kontrolü: hedef veritabanında nesne kalmış mı?
        $remaining = [];

        $stmt = $pdo->prepare("
            SELECT TABLE_NAME, TABLE_TYPE
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = ?
            ORDER BY TABLE_NAME
        ");
        $stmt->execute([$dbName]);
        $remainingTables = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $stmt->closeCursor();

        foreach ($remainingTables as $row) {
            $remaining[] = [
                'object' => (string)$row['TABLE_NAME'],
                'type' => (string)$row['TABLE_TYPE']
            ];
        }

        $stmt = $pdo->prepare("
            SELECT TRIGGER_NAME
            FROM information_schema.TRIGGERS
            WHERE TRIGGER_SCHEMA = ?
        ");
        $stmt->execute([$dbName]);
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $name) {
            $remaining[] = [
                'object' => (string)$name,
                'type' => 'TRIGGER'
            ];
        }
        $stmt->closeCursor();

        $stmt = $pdo->prepare("
            SELECT ROUTINE_NAME, ROUTINE_TYPE
            FROM information_schema.ROUTINES
            WHERE ROUTINE_SCHEMA = ?
        ");
        $stmt->execute([$dbName]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $remaining[] = [
                'object' => (string)$row['ROUTINE_NAME'],
                'type' => (string)$row['ROUTINE_TYPE']
            ];
        }
        $stmt->closeCursor();

        $stmt = $pdo->prepare("
            SELECT EVENT_NAME
            FROM information_schema.EVENTS
            WHERE EVENT_SCHEMA = ?
        ");
        $stmt->execute([$dbName]);
        foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $name) {
            $remaining[] = [
                'object' => (string)$name,
                'type' => 'EVENT'
            ];
        }
        $stmt->closeCursor();

        if ($remaining) {
            Logger::error(
                "Veritabanı tamamen temizlenemedi. Kalan nesne sayısı: " .
                count($remaining)
            );

            release_system_lock($emptyLock);
            json_response(false, 'Veritabanında silinemeyen nesneler kaldı.', [
                'dropped' => count($dropped),
                'failed' => $failed,
                'remaining' => $remaining
            ], 500);
        }

        Logger::warning(
            "VERİTABANI TAMAMEN TEMİZLENDİ: {$dbName}. " .
            "Silinen nesne sayısı: " . count($dropped)
        );

        release_system_lock($emptyLock);
        json_response(true, 'Veritabanı tamamen temizlendi. Hiçbir tablo veya veritabanı nesnesi kalmadı.', [
            'database' => $dbName,
            'dropped' => count($dropped),
            'failed' => [],
            'remaining' => []
        ]);

    } catch (Throwable $e) {
        // Beklenmeyen hatada da foreign key kontrollerini açık bırak.
        try {
            $pdo->exec("SET FOREIGN_KEY_CHECKS=1");
        } catch (Throwable $ignored) {}

        Logger::error(
            "Veritabanı tamamen temizleme hatası: " .
            get_class($e) . ' - ' . $e->getMessage()
        );

        release_system_lock($emptyLock);
        json_response(false, 'Veritabanı tamamen temizlenemedi: ' . $e->getMessage(), [], 500);
    }
}

if ($action === 'download_backup') {
    require_post();
    $file = $_POST['file'] ?? '';
    if (!is_string($file) || !validate_backup_filename($file)) {
        json_response(false, 'Yalnızca geçerli .sql.gz yedek dosyaları indirilebilir.', [], 400);
    }
    $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
    if (!is_file($safe_path)) {
        json_response(false, 'İstenen yedek dosyası sistemde bulunamadı.', [], 404);
    }
    Logger::info('Yedek indirme isteği: ' . $file);
    clear_buffers();
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('Content-Description: File Transfer');
    header('Content-Type: application/gzip');
    header('Content-Disposition: attachment; filename="' . basename($safe_path) . '"');
    header('Content-Length: ' . filesize($safe_path));
    readfile($safe_path);
    exit;
}

        if ($action === 'delete_backup') {
            require_post();
    Logger::warning('Yedek silme işlemi başlatıldı: ' . (string)($_POST['file'] ?? ''));
            $file = $_POST['file'] ?? '';
            if (!is_string($file) || !validate_backup_filename($file)) {
                json_response(false, 'Yalnızca geçerli .sql.gz yedek dosyaları silinebilir.', [], 400);
            }
            $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);

            if (is_file($safe_path)) {
                unlink($safe_path);
                $sha_file = $safe_path . '.sha256';
                if (is_file($sha_file)) @unlink($sha_file);
                $meta_file = $safe_path . '.meta.json';
                if (is_file($meta_file)) @unlink($meta_file);
                Logger::info("Yedek dosyası silindi: {$file}");
                json_response(true, 'Yedek dosyası başarıyla silindi.');
            } else {
                json_response(false, 'Silinecek dosya bulunamadı.');
            }
        }

        if ($action === 'check_integrity') {
            require_post();
            if (!verify_csrf_token((string)($_POST['csrf_token'] ?? ''))) {
                json_response(false, 'CSRF doğrulaması başarısız.', [], 403);
            }
            Logger::info('Yedek bütünlük kontrolü başlatıldı: ' . (string)($_POST['file'] ?? ''));
            $file = $_POST['file'] ?? '';
            if (!is_string($file) || !validate_backup_filename($file)) {
                json_response(false, 'Yalnızca geçerli .sql.gz yedek dosyaları doğrulanabilir.', [], 400);
            }
            $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);

            $validation = validate_backup_restore_compatibility($safe_path);
            $hash = verify_backup_checksum($safe_path);
            json_response(true, 'Bütünlük + test restore doğrulaması BAŞARILI.', ['hash' => $hash, 'restore_validation' => $validation]);
        }

        if ($action === 'clear_logs') {
            require_post();
            $log_path = $backup_dir . '/system.log';
            if (is_file($log_path)) {
                safe_file_put_contents($log_path, '');
                Logger::info("Sistem logları kullanıcı tarafından temizlendi.");
            }
            json_response(true, 'Loglar başarıyla temizlendi.');
        }

        // Varsayılan seçim CLI'dir; WEB seçilirse Web Worker zorunlu olarak kullanılır.
        if ($action === 'restore_chunk') {
            require_post();
            $file = (string)($_POST['file'] ?? '');
            if (!validate_backup_filename($file)) {
                json_response(false, 'Geçersiz veya güvenli olmayan yedek dosyası.', [], 400);
            }
            $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
            if (!is_file($safe_path)) {
                json_response(false, 'Yedek dosyası bulunamadı.', [], 404);
            }

            $worker_mode = strtolower(trim((string)($_POST['worker_mode'] ?? 'cli')));
            if (!in_array($worker_mode, ['cli', 'web'], true)) {
                json_response(false, 'Geçersiz çalışma modu. CLI veya WEB seçilmelidir.', [], 400);
            }

            $job_id = bin2hex(random_bytes(16));

            if ($worker_mode === 'cli') {
                $cli = detect_cli_worker_capability();
                if (!$cli['available']) {
                    Logger::error('CLI RESTORE BAŞLATILAMADI | kullanıcı modu=CLI | file=' . $file . ' | neden=' . ($cli['reason'] ?: 'CLI worker kullanılamıyor.'));
                    json_response(false, 'CLI worker bu sunucuda kullanılamıyor. Çalışma Modu bölümünden WEB seçerek devam edebilirsiniz.', [
                        'engine' => 'cli',
                        'cli_available' => false,
                        'reason' => $cli['reason']
                    ], 503);
                }
                if (spawn_cli_job(__FILE__, $config['cron_token'], 'restore', $job_id, $file)) {
                    json_response(true, 'CLI restore arka planda başlatıldı.', [
                        'status' => 'starting',
                        'percent' => 0,
                        'job_id' => $job_id,
                        'file' => $file,
                        'engine' => 'cli'
                    ]);
                }
                Logger::error('CLI RESTORE BAŞLATILAMADI | kullanıcı modu=CLI | job_id=' . $job_id . ' | file=' . $file);
                json_response(false, 'CLI restore süreci başlatılamadı. Çalışma Modu bölümünden WEB seçerek devam edebilirsiniz.', [
                    'engine' => 'cli',
                    'job_id' => $job_id
                ], 503);
            }

            $config['_web_fallback_reason'] = 'Kullanıcı WEB çalışma modunu seçti.';
            $state = initialize_web_restore_job($pdo, $backup_dir, $config, $job_id, $file);
            json_response(true, 'Web Worker restore başlatıldı.', [
                'status' => $state['status'],
                'percent' => 0,
                'job_id' => $job_id,
                'file' => $file,
                'engine' => 'web'
            ]);
        }

        if ($action === 'get_cli_job_progress') {
            require_post();
            $job_id = (string)($_POST['job_id'] ?? '');
            if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
                json_response(false, 'Geçersiz CLI job ID.', [], 400);
            }
            $state = read_cli_job_state($backup_dir, $job_id);
            if (!$state) {
                json_response(true, 'CLI job henüz başlamadı.', [
                    'status' => 'starting',
                    'percent' => 0,
                    'job_id' => $job_id
                ]);
            }
            json_response(true, 'CLI job durumu alındı.', $state);
        }

    } catch (Throwable $e) {
        Logger::error("API İşlem Hatası ({$action}): " . get_class($e) . ' - ' . $e->getMessage());
        json_response(false, 'API işlem hatası: ' . $e->getMessage(), [], 500);
    }
}

$cli_cron_command = 'php ' . escapeshellarg(__FILE__) . ' ' . $config['cron_token'];
clear_buffers();
?>
<!DOCTYPE html>
<html lang="tr">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VEDO MySQL Backup & Enterprise Panel</title>
    <style nonce="<?= $nonce ?>">
        :root {
            color-scheme: dark;
            --bg: #0b1016;
            --panel: #141b23;
            --panel-border: #2b3744;
            --text: #edf3f8;
            --text-secondary: #93a1ae;
            --surface: #141b23;
            --surface-2: #10161d;
            --surface-3: #1b2530;
            --line: #2b3744;
            --line-soft: #222c36;
            --text-2: #c7d1da;
            --muted: #93a1ae;
            --primary: #579cff;
            --primary-soft: #172a45;
            --success: #3fcf7f;
            --danger: #ef6464;
            --warning: #f4b94f;
            --shadow: 0 5px 20px rgba(0,0,0,.22);
            --radius: 10px;
            --accent-green: #3fcf7f;
            --accent-green-hover: #35b66c;
            --accent-red: #ef6464;
            --accent-red-hover: #d95353;
            --accent-blue: #579cff;
            --accent-blue-hover: #4588e6;
            --accent-warning: #f4b94f;
            --accent-info: #4ec3d8;
        }

        /* AÇIK TEMA: yalnızca .theme-light sınıfı ile etkinleştirilir. */
        html.theme-light {
            color-scheme: light;
            --bg: #f5f7fa;
            --panel: #ffffff;
            --panel-border: #d7e0e8;
            --text: #17212b;
            --text-secondary: #6c7a88;
            --surface: #ffffff;
            --surface-2: #f7f9fc;
            --surface-3: #edf2f7;
            --line: #d7e0e8;
            --line-soft: #e6ecf2;
            --text-2: #43515f;
            --muted: #6c7a88;
            --primary: #2f7de1;
            --primary-soft: #e8f1ff;
            --success: #168a4d;
            --danger: #c93b3b;
            --warning: #b77900;
            --shadow: 0 5px 20px rgba(36,55,75,.10);
            --accent-green: #168a4d;
            --accent-green-hover: #11703e;
            --accent-red: #c93b3b;
            --accent-red-hover: #aa3030;
            --accent-blue: #2f7de1;
            --accent-blue-hover: #2467bd;
            --accent-warning: #b77900;
            --accent-info: #197b8c;
        }

        * { box-sizing: border-box; }
        body {
            background-color: var(--bg);
            color: var(--text);
            font-family: var(--vedo-ui-font) !important;
            margin: 0;
            padding: 20px;
        }

        .container { max-width: 1300px; margin: 0 auto; }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--panel-border);
        }

        header h1 { margin: 0; font-size: 24px; color: var(--text); }
        header .actions { display: flex; gap: 10px; }

        .btn {
            padding: 9px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

        .btn-green { background: var(--accent-green); color: #fff; }
        .btn-green:hover { background: var(--accent-green-hover); }
        .btn-red { background: var(--accent-red); color: #fff; }
        .btn-red:hover { background: var(--accent-red-hover); }
        .btn-blue { background: var(--accent-blue); color: #fff; }
        .btn-blue:hover { background: var(--accent-blue-hover); }
        .btn-secondary { background: var(--surface-3); color: var(--text); border: 1px solid var(--line); }
        .btn-secondary:hover { background: var(--line-soft); }
        #btnThemeToggle:focus-visible { outline: 2px solid var(--primary); outline-offset: 2px; }

        .grid-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .card {
            background-color: var(--panel);
            border: 1px solid var(--panel-border);
            border-radius: 6px;
            padding: 15px;
        }

        .card-title {
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        .card-value {
            font-size: 20px;
            color: var(--text);
        }

        .card-sub {
            color: var(--text-secondary);
            margin-top: 5px;
        }

        .progress-bar-bg {
            background: var(--surface-3);
            height: 6px;
            border-radius: 3px;
            overflow: hidden;
            margin-top: 8px;
        }

        .progress-bar-fill {
            background: var(--accent-blue);
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }

        .section-title {
            font-size: 16px;
            margin-bottom: 12px;
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-box {
            background-color: var(--panel);
            border: 1px solid var(--panel-border);
            border-radius: 6px;
            padding: 15px;
            margin-bottom: 25px;
        }

        /* Live Progress Panel */
        #live-progress-panel {
            border-left: 4px solid var(--accent-blue);
            display: none;
        }

        .progress-info-grid {
            display: grid;
            grid-template-columns: minmax(170px, 1.55fr) repeat(6, minmax(92px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }

        @media (max-width: 1100px) {
            .progress-info-grid {
                grid-template-columns: repeat(4, minmax(120px, 1fr));
            }
        }

        @media (max-width: 700px) {
            .progress-info-grid {
                grid-template-columns: repeat(2, minmax(120px, 1fr));
            }
        }

        .progress-info-item {
            background: var(--surface-2);
            padding: 8px;
            border-radius: 4px;
        }

        .progress-info-item span { display: block; color: var(--text-secondary); font-size: 12px; }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--panel-border);
        }

        th {
            background-color: var(--surface-2);
            color: var(--text-secondary);
            font-weight: 500;
        }

        tr:hover { background-color: var(--surface-3); }

        .badge {
            padding: 3px 8px;
            border-radius: 3px;
        }
        .badge-success { background: rgba(40, 167, 69, 0.2); color: #28a745; }
        .badge-warning { background: rgba(255, 193, 7, 0.2); color: #ffc107; }
        .badge-danger { background: rgba(220, 53, 69, 0.2); color: #dc3545; }

        /* Logs Panel */
        .log-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }

        .log-controls input, .log-controls select {
            background: var(--surface-2);
            border: 1px solid var(--line);
            color: var(--text);
            padding: 6px 10px;
            border-radius: 4px;
        }

        .log-box {
            background: #0a0a0a;
            border: 1px solid var(--panel-border);
            border-radius: 4px;
            padding: 10px;
            height: 180px;
            min-height: 180px;
            overflow-y: auto;
            font-family: var(--vedo-ui-font) !important;
            line-height: 1.55;
            color: #ffe082;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .log-line-INFO { color: #81d4fa; }
        .log-line-WARNING { color: #ffe082; }
        .log-line-ERROR { color: #ef9a9a; }

        /* LOG MODAL: Çok sayıda kayıt için SQL Gezgini benzeri geniş görünüm. */
        .log-modal-overlay {
            position: fixed;
            inset: 0;
            z-index: 3000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 24px;
            background: rgba(0,0,0,.55);
        }
        .log-modal-overlay.open { display: flex; }
        .log-modal {
            width: min(1400px, 96vw);
            height: min(820px, 92vh);
            background: var(--surface);
            color: var(--text);
            border: 1px solid var(--panel-border);
            border-radius: 8px;
            box-shadow: 0 20px 60px rgba(0,0,0,.35);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        .log-modal-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            padding: 12px 14px;
            border-bottom: 1px solid var(--line);
            background: var(--surface-2);
        }
        .log-modal-title { font-weight: 500; }
        .log-modal-body { flex: 1; min-height: 0; padding: 12px; }
        .log-modal-body .log-box { height: 100%; min-height: 0; box-sizing: border-box; }
        .theme-dark .log-modal-overlay { background: rgba(0,0,0,.72); }

        /* DB gezgini */
        .db-explorer { display:grid; grid-template-columns:280px minmax(0,1fr); gap:15px; }
        .db-sidebar { background:var(--surface-2); border:1px solid var(--line); border-radius:5px; max-height:560px; overflow:auto; }
        .db-table-item { padding:9px 10px; border-bottom:1px solid var(--line-soft); cursor:pointer; display:flex; justify-content:space-between; gap:8px; }
        .db-table-item:hover,.db-table-item.active { background:var(--primary-soft); }
        .db-table-item small { color:var(--text-secondary); }
        .db-main { min-width:0; }
        .db-toolbar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:10px; }
        .db-toolbar select,.db-toolbar input { background:var(--surface-2); border:1px solid var(--line); color:var(--text); padding:7px 9px; border-radius:4px; }
        .db-data-wrap { overflow:auto; max-height:430px; border:1px solid var(--panel-border); border-radius:5px; }
        .db-data-wrap table { min-width:700px; }
        .db-data-wrap td { max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        /* CLI CRON: Açıklama ve komutun tek, düzenli kutu görünümünü sağlar. */
    /* CLI CRON: Açıklama, komut ve butonu tek satırda ve taşma olmadan gösterir. */
    .cron-box-compact {
        display: grid;
        grid-template-columns: max-content minmax(180px, 1fr) minmax(500px, 2fr) max-content;
        grid-template-areas: "title description code button";
        align-items: center;
        gap: 8px;
        width: 100%;
        min-width: 0;
        min-height: 44px;
        padding: 7px 9px;
        box-sizing: border-box;
        overflow: hidden;
    }

    .cron-box-compact .cron-title {
        grid-area: title;
        display: inline-block;
        min-width: 0;
        margin: 0;
        padding: 0;
        white-space: nowrap;
        font-family: var(--vedo-ui-font) !important;
        font-weight: 500;
        line-height: 1.25;
    }

    .cron-box-compact .cron-description {
        grid-area: description;
        min-width: 0;
        margin: 0;
        padding: 0;
        color: var(--text-secondary);
        font-family: var(--vedo-ui-font) !important;
        font-weight: 500;
        line-height: 1.35;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: clip;
    }

    /* CLI CRON: Açık temada kutu ve komut alanı açık renkte tutulur; koyu temada değişkenler otomatik devreye girer. */
    .cron-code-inline {
        grid-area: code;
        display: block;
        width: 100%;
        min-width: 0;
        height: 30px;
        box-sizing: border-box;
        margin: 0;
        padding: 5px 7px;
        border: 1px solid var(--line);
        border-radius: 5px;
        background: var(--surface-2);
        color: var(--text);
        font-family: var(--vedo-ui-font) !important;
        font-weight: 500;
        line-height: 16px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .cron-box-compact .cron-copy-btn {
        grid-area: button;
        position: static;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 70px;
        min-width: 70px;
        max-width: 70px;
        height: 30px;
        margin: 0;
        padding: 0 10px;
        box-sizing: border-box;
        font-family: var(--vedo-ui-font) !important;
        font-weight: 500;
        line-height: 1;
        white-space: nowrap;
        overflow: visible;
    }

    @media (max-width: 900px) {
        .cron-box-compact {
            grid-template-columns: max-content minmax(0, 1fr) 460px max-content;
            grid-template-areas: "title description code button";
            min-height: 0;
        }
        .cron-box-compact .cron-description {
            min-width: 0;
        }
    }

    .cron-box {
        position: relative;
    }

    .cron-description {
        margin-top: 8px;
        color: var(--text-secondary);
        line-height: 1.6;
        max-width: 100%;
    }

    .cron-command-wrap {
        position: relative;
        margin-top: 14px;
        padding: 12px;
        border: 1px solid var(--line);
        border-radius: 8px;
        background: var(--surface-2);
    }

    .cron-command-label {
        margin-bottom: 7px;
        color: var(--text-secondary);
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: .04em;
    }

    .cron-code-block {
        margin: 0;
        padding: 12px 96px 12px 12px;
        min-height: 20px;
        overflow-x: auto;
        border-radius: 6px;
        background: var(--code-bg, #111827);
        color: var(--code-text, #e5e7eb);
        font-family: var(--vedo-ui-font) !important;
        line-height: 1.5;
        white-space: pre-wrap;
        word-break: break-all;
    }

    .cron-copy-btn {
        position: absolute;
        top: 34px;
        right: 20px;
        padding: 5px 9px;
    }

    /* CLI Cron kutusunda kopyalama butonu normal grid akışında kalır ve alta taşmaz. */
    .cron-box-compact .cron-copy-btn {
        position: static;
        top: auto;
        right: auto;
    }

    .cron-box { background:var(--panel); border:1px solid var(--panel-border); border-left:4px solid var(--accent-blue); border-radius:6px; padding:12px 14px; margin-bottom:20px; }
        .cron-title { display:block; color:var(--text-secondary); margin-bottom:7px; }
        .cron-line { display:flex; gap:8px; align-items:center; }
        .cron-code { flex:1; min-width:0; background:var(--surface-2); border:1px solid var(--line); color:var(--text); padding:9px; border-radius:4px; font-family: var(--vedo-ui-font) !important; }
        @media (max-width:800px){ .db-explorer{grid-template-columns:1fr;} .db-sidebar{max-height:240px;} .cron-line{flex-direction:column;align-items:stretch;} }

        /* Veritabanı Gezgini penceresi */
        .db-explorer-overlay {
            position: fixed;
            inset: 0;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 24px;
            background: rgba(0,0,0,.82);
            z-index: 3000;
            backdrop-filter: blur(3px);
        }
        .db-explorer-overlay.open { display: flex; }
        .db-explorer-modal {
            width: min(1450px, 96vw);
            height: min(900px, 92vh);
            display: flex;
            flex-direction: column;
            background: var(--panel);
            border: 1px solid #3b3b3b;
            border-radius: 8px;
            box-shadow: 0 24px 80px rgba(0,0,0,.55);
            overflow: hidden;
        }
        .db-explorer-modal-head {
            flex: 0 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 15px;
            padding: 13px 16px;
            background: var(--surface-2);
            border-bottom: 1px solid var(--line);
        }
        .db-explorer-modal-title { font-weight: 500; color: #fff; }
        .db-explorer-modal-subtitle { margin-top: 3px; color: var(--text-secondary); }
        .db-explorer-modal-body { flex: 1 1 auto; min-height: 0; overflow: hidden; padding: 14px; }
        .db-explorer-modal-body > .panel-box { height: 100%; margin: 0; padding: 0; border: 0; background: transparent; overflow: hidden; }
        .db-explorer-modal-body .section-title { padding: 0 0 10px; }
        .db-explorer-modal-body .db-explorer { height: calc(100% - 40px); min-height: 0; }
        .db-explorer-modal-body .db-sidebar { max-height: none; height: 100%; }
        .db-explorer-modal-body .db-main { height: 100%; display: flex; flex-direction: column; min-height: 0; }
        .db-explorer-modal-body .db-data-wrap { flex: 1 1 auto; max-height: none; min-height: 180px; }
        .db-explorer-close {
            width: 34px; height: 34px; padding: 0; border-radius: 5px;
            border: 1px solid var(--line); background: var(--surface-3); color: var(--text);
            font-size: 20px; line-height: 1; cursor: pointer;
        }
        .db-explorer-close:hover { background: var(--line-soft); }
        body.db-modal-open { overflow: hidden; }
        @media (max-width: 800px) {
            .db-explorer-overlay { padding: 8px; }
            .db-explorer-modal { width: 100%; height: 96vh; }
            .db-explorer-modal-body { padding: 10px; }
        }

        /* Toast — kompakt uyarı balonları */
        #toast-container {
            position: fixed;
            right: 18px;
            bottom: 18px;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 6px;
            width: min(360px, calc(100vw - 36px));
            pointer-events: none;
        }

        .toast {
            width: fit-content;
            max-width: 360px;
            min-width: 180px;
            box-sizing: border-box;
            background: var(--surface-3);
            color: var(--text);
            padding: 8px 11px;
            border-radius: 7px;
            margin-top: 0;
            border: 1px solid var(--line);
            border-left: 3px solid var(--accent-blue);
            box-shadow: 0 4px 14px rgba(0,0,0,.28);
            font-size: 12px !important;
            line-height: 1.35 !important;
            font-weight: 500;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: break-word;
            pointer-events: auto;
            animation: fadeIn 0.22s ease-out;
        }

        .toast-error { border-left-color: var(--accent-red); }
        .toast-success { border-left-color: var(--accent-green); }

        @media (max-width: 560px) {
            #toast-container {
                right: 10px;
                bottom: 10px;
                width: calc(100vw - 20px);
            }
            .toast {
                max-width: min(340px, calc(100vw - 20px));
                min-width: 0;
                padding: 7px 10px;
                font-size: 12px !important;
            }
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

.container,.dashboard-container,.main-container{
    width:min(1480px,94vw)!important;
    max-width:1480px!important;
    margin:0 auto!important;
}
header,.topbar,.header{
    background:var(--surface-2)!important;
    color:var(--text)!important;
    border-bottom:1px solid var(--line)!important;
    box-shadow:0 1px 0 rgba(255,255,255,.02)!important;
}
@media(max-width:850px){
    .container,.dashboard-container,.main-container{width:96vw!important}
    .card-value{font-size:26px!important}
    #bulkDeleteBackupsBtn{margin-left:0!important}
}

/* ==========================================================
   VEDO TİPOGRAFİ — TEK STANDARD
   Tüm panel tek sistem fontu ve sade bir ölçü hiyerarşisi kullanır.
   ========================================================== */
:root {
    --vedo-ui-font: <?= htmlspecialchars($config['ui_font'], ENT_QUOTES, 'UTF-8') ?>;
}

html,
body,
body *,
button,
input,
select,
textarea,
table,
caption,
thead,
tbody,
tfoot,
tr,
th,
td,
label,
a,
strong,
b,
em,
small,
span,
div {
    font-family: var(--vedo-ui-font) !important;
    font-synthesis: none;
}


body {
    font-size: 14px !important;
    line-height: 1.45 !important;
    font-weight: 400 !important;
}

h1 { font-size: 24px !important; line-height: 1.25 !important; font-weight: 500 !important; }
h2 { font-size: 20px !important; line-height: 1.3 !important; font-weight: 500 !important; }
h3 { font-size: 18px !important; line-height: 1.35 !important; font-weight: 500 !important; }
h4, h5, h6 { font-size: 16px !important; line-height: 1.4 !important; font-weight: 500 !important; }

.section-title, .panel-title {
    font-size: 18px !important;
    line-height: 1.35 !important;
    font-weight: 500 !important;
}

.card-title {
    font-size: 13px !important;
    line-height: 1.4 !important;
    font-weight: 500 !important;
}

.card-value {
    font-size: 26px !important;
    line-height: 1.15 !important;
    font-weight: 500 !important;
    letter-spacing: -0.01em !important;
}

#m-mysql-ver {
    font-size: 15px !important;
    line-height: 1.25 !important;
    font-weight: 500 !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
    display: block !important;
    max-width: 100% !important;
    margin-top: 5px !important;
}

.card-sub, .info-item span, .progress-info-item span {
    font-size: 13px !important;
    line-height: 1.45 !important;
    font-weight: 400 !important;
}

.info-item strong, .progress-info-item strong {
    font-size: 14px !important;
    line-height: 1.45 !important;
    font-weight: 500 !important;
}

.btn, button {
    font-size: 14px !important;
    line-height: 1.35 !important;
    font-weight: 500 !important;
}

input, select, textarea {
    font-size: 14px !important;
    line-height: 1.4 !important;
    font-weight: 400 !important;
}

table { font-size: 13px !important; }
th { font-size: 12px !important; line-height: 1.35 !important; font-weight: 500 !important; }
td { font-size: 13px !important; line-height: 1.45 !important; font-weight: 400 !important; }

.badge {
    font-size: 12px !important;
    line-height: 1.25 !important;
    font-weight: 500 !important;
}

.toast, .db-table-item {
    font-size: 13px !important;
    line-height: 1.45 !important;
}

.db-toolbar strong {
    font-size: 17px !important;
    font-weight: 500 !important;
}

@media (max-width: 560px) {
    h1 { font-size: 22px !important; }
    h2 { font-size: 19px !important; }
    h3 { font-size: 17px !important; }
    .section-title, .panel-title { font-size: 17px !important; }
    .card-value { font-size: 24px !important; }
}

/* ==========================================================
   LOG EKRANI — TERMINAL GÖRÜNÜMÜ
   ========================================================== */
.log-box,
#logBoxContainer{
    color:#ffd84d !important;
    background:#050505 !important;
    border:1px solid #242424 !important;
    font-size:15px !important;
    line-height:1.65 !important;
    font-weight:500 !important;
    letter-spacing:.01em !important;
    text-shadow:0 0 3px rgba(255,216,77,.10);
    user-select:text !important;
    -webkit-user-select:text !important;
    cursor:text !important;
}
.log-box *,
#logBoxContainer * {
    user-select:text !important;
    -webkit-user-select:text !important;
}
.log-box .log-line-INFO,#logBoxContainer .log-line-INFO,
.log-box .log-line-WARNING,#logBoxContainer .log-line-WARNING,
.log-box .log-line-ERROR,#logBoxContainer .log-line-ERROR{
    color:#ffd84d !important;
}
.log-controls input,.log-controls select{
    font-family: var(--vedo-ui-font) !important;
}

/* Theme toggle */
.theme-toggle-btn{min-width:125px!important}

        /* ==========================================================
           VEDO — DATABASE EXPLORER: LIGHT THEME, FULL SURFACE RESET
           Açık temada bu pencerenin hiçbir bölümü koyu zemin kullanmaz.
           ========================================================== */
        html.theme-light .db-explorer-overlay {
            background: rgba(245,247,250,.78) !important;
            backdrop-filter: blur(3px);
        }
        html.theme-light .db-explorer-modal,
        html.theme-light .db-explorer-modal-head,
        html.theme-light .db-explorer-modal-body,
        html.theme-light .db-explorer-modal-body > .panel-box,
        html.theme-light #dbExplorerPanel,
        html.theme-light .db-main,
        html.theme-light .db-toolbar,
        html.theme-light .db-data-wrap,
        html.theme-light .db-data-wrap table {
            background: var(--surface) !important;
            color: var(--text) !important;
        }
        html.theme-light .db-explorer-modal {
            border: 1px solid var(--line) !important;
            box-shadow: 0 24px 70px rgba(36,55,75,.16) !important;
        }
        html.theme-light .db-explorer-modal-head {
            border-bottom: 1px solid var(--line) !important;
        }
        html.theme-light .db-explorer-modal-title,
        html.theme-light #dbSelectedTable {
            color: var(--text) !important;
        }
        html.theme-light .db-explorer-modal-subtitle,
        html.theme-light #dbTableMeta,
        html.theme-light #dbPageInfo,
        html.theme-light .db-sidebar > div[style],
        html.theme-light .db-data-wrap > div[style] {
            color: var(--muted) !important;
        }
        html.theme-light .db-sidebar {
            background: var(--surface-2) !important;
            color: var(--text-2) !important;
            border: 1px solid var(--line) !important;
        }
        html.theme-light .db-table-item,
        html.theme-light .db-table-item:hover,
        html.theme-light .db-table-item.active {
            color: var(--text-2) !important;
            border-bottom: 1px solid var(--line-soft) !important;
        }
        html.theme-light .db-table-item { background: var(--surface-2) !important; }
        html.theme-light .db-table-item:hover,
        html.theme-light .db-table-item.active {
            background: var(--primary-soft) !important;
            color: var(--text) !important;
        }
        html.theme-light .db-table-item small { color: var(--muted) !important; }
        html.theme-light .db-toolbar select,
        html.theme-light .db-toolbar input {
            background: var(--surface-2) !important;
            color: var(--text) !important;
            border: 1px solid var(--line) !important;
        }
        html.theme-light .db-data-wrap {
            border: 1px solid var(--line) !important;
        }
        html.theme-light .db-data-wrap thead,
        html.theme-light .db-data-wrap thead tr,
        html.theme-light .db-data-wrap thead th {
            background: var(--surface-2) !important;
            color: var(--text-2) !important;
            border-color: var(--line) !important;
        }
        html.theme-light .db-data-wrap tbody,
        html.theme-light .db-data-wrap tbody tr,
        html.theme-light .db-data-wrap tbody td {
            background: var(--surface) !important;
            color: var(--text-2) !important;
            border-color: var(--line-soft) !important;
        }
        html.theme-light .db-data-wrap tbody tr:hover td {
            background: var(--surface-3) !important;
        }
        html.theme-light .db-explorer-close {
            background: var(--surface-3) !important;
            color: var(--text) !important;
            border: 1px solid var(--line) !important;
        }
        html.theme-light .db-explorer-close:hover {
            background: var(--line-soft) !important;
        }
        html.theme-light .db-explorer-modal .section-title {
            color: var(--text) !important;
            border-bottom-color: var(--line) !important;
        }
        html.theme-light .db-explorer-modal .btn-secondary {
            background: var(--surface-2) !important;
            color: var(--text) !important;
            border-color: var(--line) !important;
        }

        /* Canlı ilerleme kartları: açık temada koyu kutu kullanma. */
        html.theme-light #live-progress-panel .progress-info-item {
            background: var(--surface-2) !important;
            color: var(--text) !important;
            border: 1px solid var(--line-soft) !important;
            box-shadow: none !important;
        }
        html.theme-light #live-progress-panel .progress-info-item span {
            color: var(--muted) !important;
        }
        html.theme-light #live-progress-panel .progress-info-item strong {
            color: var(--text) !important;
        }
        html.theme-light #live-progress-panel .progress-bar-bg {
            background: var(--surface-3) !important;
        }
        html.theme-light #live-progress-panel,
        html.theme-light #live-progress-panel .section-title,
        html.theme-light #live-progress-panel > div {
            color: var(--text) !important;
        }

        /* ÇALIŞMA MODU: Büyük ve başlığın yanında görünür; varsayılan CLI'dır. */
        .header-title-row {
            display: flex;
            align-items: center;
            gap: 22px;
            flex-wrap: wrap;
        }
        .worker-mode-control {
            display: inline-flex;
            align-items: center;
            gap: 14px;
            color: var(--text);
            font-size: 18px;
            line-height: 1.1;
            font-weight: 500;
            white-space: nowrap;
        }
        .worker-mode-title {
            color: var(--text-secondary);
            font-weight: 500;
            margin: 0 2px 0 0;
        }
        .worker-mode-checkbox {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            user-select: none;
            margin: 0;
            color: var(--text);
            font-weight: 500;
        }
        .worker-mode-checkbox input {
            width: 22px;
            height: 22px;
            margin: 0;
            accent-color: var(--primary);
            cursor: pointer;
        }
        .worker-mode-control span#workerModeStatus {
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
        }
        /* ÇALIŞMA MODU TAVSİYESİ: CLI Cron kutusu ile aynı görsel dilde, CPU kartının hemen üstünde yer alır. */
        .worker-mode-advice-box {
            position: relative;
            margin: 0 0 18px;
            padding: 10px 14px;
            border: 1px solid var(--panel-border);
            border-left: 4px solid var(--accent-warning);
            border-radius: 6px;
            background: var(--panel);
            color: var(--text-secondary);
            font-size: 17px;
            line-height: 1.25;
            font-weight: 500;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .worker-mode-advice-box strong {
            color: var(--accent-warning);
        }
        @media (max-width: 900px) {
            .header-title-row {
                gap: 14px;
            }
            .worker-mode-control {
                font-size: 16px;
                gap: 11px;
            }
            .worker-mode-checkbox input {
                width: 20px;
                height: 20px;
            }
        }

        /* Sunucu Bilgileri */
        .server-info-overlay {
            position: fixed;
            inset: 0;
            z-index: 1300;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 22px;
            background: rgba(0,0,0,.72);
            backdrop-filter: blur(4px);
        }
        .server-info-overlay.open { display: flex; }
        .server-info-modal {
            width: min(1180px, 96vw);
            max-height: 92vh;
            overflow: hidden;
            background: var(--panel);
            border: 1px solid var(--panel-border);
            border-radius: 14px;
            box-shadow: 0 24px 80px rgba(0,0,0,.45);
            color: var(--text);
        }
        .server-info-modal-head {
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:16px;
            padding:18px 20px;
            border-bottom:1px solid var(--line);
            background:var(--surface-2);
        }
        .server-info-modal-title { font-size:20px; font-weight: 500; }
        .server-info-modal-subtitle { margin-top:4px; color:var(--text-secondary); }
        .server-info-head-actions { display:flex; align-items:center; gap:8px; }
        .server-info-close {
            width:36px; height:36px; border-radius:8px; border:1px solid var(--line);
            background:var(--surface-3); color:var(--text); font-size:25px; line-height:1; cursor:pointer;
        }
        .server-info-modal-body { padding:20px; overflow:auto; max-height:calc(92vh - 78px); }
        .server-gauge-grid {
            display:grid; grid-template-columns:repeat(3,minmax(160px,1fr)); gap:16px; margin-bottom:20px;
        }
        .server-gauge-card {
            background:var(--surface-2); border:1px solid var(--line); border-radius:12px;
            padding:18px; text-align:center;
        }
        .server-gauge {
            --gauge-value:0%;
            width:142px; height:142px; margin:0 auto 10px; border-radius:50%;
            display:grid; place-items:center;
            background:conic-gradient(var(--accent-blue) var(--gauge-value), var(--surface-3) 0);
            position:relative;
        }
        .server-gauge::before {
            content:""; position:absolute; inset:10px; border-radius:50%; background:var(--panel);
            border:1px solid var(--line);
        }
        .server-gauge-inner {
            position:relative; z-index:1; display:flex; flex-direction:column; align-items:center; gap:2px;
        }
        .server-gauge-inner strong { font-size:28px; font-weight: 500; letter-spacing:-.5px; }
        .server-gauge-inner span { color:var(--text-secondary); text-transform:uppercase; letter-spacing:.08em; }
        .server-gauge-meta { color:var(--text-secondary); min-height:18px; }
        .server-info-grid {
            display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px;
        }
        .server-info-section {
            min-width:0; background:var(--surface-2); border:1px solid var(--line);
            border-radius:10px; overflow:hidden;
        }
        .server-info-full { grid-column:1/-1; }
        .server-info-section-title {
            padding:11px 13px; font-weight: 500; color:var(--text);
            border-bottom:1px solid var(--line); background:var(--surface-3);
        }
        .server-info-table { display:grid; grid-template-columns:minmax(150px, 38%) 1fr; }
        .server-info-row { display:contents; }
        .server-info-key, .server-info-value {
            padding:8px 12px; border-bottom:1px solid var(--line-soft);
        }
        .server-info-key { color:var(--text-secondary); }
        .server-info-value { color:var(--text); font-weight:500; overflow-wrap:anywhere; }
        .server-extension-list { display:flex; flex-wrap:wrap; gap:6px; padding:12px; }
        .server-extension-badge {
            padding:5px 8px; border:1px solid var(--line); border-radius:999px;
            background:var(--surface-3); color:var(--text-secondary);
        }
        @media (max-width: 760px) {
            .server-gauge-grid, .server-info-grid { grid-template-columns:1fr; }
            .server-info-full { grid-column:auto; }
            .server-info-modal { width:98vw; }
            .server-info-modal-body { padding:12px; }
        }


        :root {
            --ui-focus: 0 0 0 3px color-mix(in srgb, var(--primary) 22%, transparent);
            --ui-glass: color-mix(in srgb, var(--panel) 88%, transparent);
            --ui-ease: cubic-bezier(.2,.7,.2,1);
        }
        *, *::before, *::after { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        body {
            text-rendering: optimizeLegibility;
            -webkit-font-smoothing: antialiased;
        }
        button, input, select, textarea { font: inherit; }
        button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible, a:focus-visible {
            outline: none;
            box-shadow: var(--ui-focus);
        }
        .card, .panel, .metric-card, .dashboard-card, .server-card, .backup-card, .log-modal, .db-explorer-modal {
            transition: transform .18s var(--ui-ease), box-shadow .18s var(--ui-ease), border-color .18s var(--ui-ease);
        }
        .card:hover, .panel:hover, .metric-card:hover, .dashboard-card:hover, .server-card:hover, .backup-card:hover {
            transform: translateY(-1px);
        }
        #toast-container {
            position: fixed;
            top: auto !important;
            bottom: 18px !important;
            right: 14px;
            z-index: 100000;
            width: auto;
            max-width: calc(100vw - 28px);
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 6px;
            pointer-events: none;
        }
        #toast-container .toast {
            width: auto !important;
            max-width: 300px !important;
            min-width: 0 !important;
            box-sizing: border-box;
            pointer-events: auto;
            display: block;
            padding: 6px 9px !important;
            margin: 0 !important;
            border: 1px solid var(--panel-border);
            border-radius: 7px;
            background: var(--ui-glass);
            color: var(--text);
            box-shadow: 0 5px 14px rgba(0,0,0,.20);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            font-size: 12px !important;
            line-height: 1.3 !important;
            font-weight: 500;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: break-word;
            max-height: 84px;
            overflow: auto;
            animation: vedoToastIn .2s var(--ui-ease);
        }
        #toast-container .toast-success { border-left: 3px solid var(--success); }
        #toast-container .toast-error { border-left: 3px solid var(--danger); }
        .vedo-confirm-overlay {
            position: fixed;
            inset: 0;
            z-index: 110000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: rgba(4,8,13,.66);
            backdrop-filter: blur(7px);
            -webkit-backdrop-filter: blur(7px);
        }
        .vedo-confirm-overlay.open { display: flex; }
        .vedo-confirm-dialog {
            width: min(480px, 100%);
            background: var(--panel);
            color: var(--text);
            border: 1px solid var(--panel-border);
            border-radius: 16px;
            box-shadow: 0 28px 80px rgba(0,0,0,.35);
            padding: 22px;
            animation: vedoDialogIn .2s var(--ui-ease);
        }
        .vedo-confirm-title { margin: 0 0 8px; font-size: 18px; font-weight: 700; }
        .vedo-confirm-message { margin: 0; color: var(--text-secondary); line-height: 1.55; }
        .vedo-confirm-actions { display:flex; justify-content:flex-end; gap:10px; margin-top:20px; }
        .vedo-confirm-actions button { min-width: 92px; }
        @keyframes vedoToastIn { from { opacity:0; transform:translateY(-8px) scale(.98); } to { opacity:1; transform:none; } }
        @keyframes vedoDialogIn { from { opacity:0; transform:translateY(8px) scale(.98); } to { opacity:1; transform:none; } }
        @media (max-width: 700px) {
            #toast-container { top: auto !important; bottom: 10px !important; right: 10px !important; max-width: calc(100vw - 20px); }
            #toast-container .toast { max-width: min(280px, calc(100vw - 20px)) !important; padding: 6px 8px !important; font-size: 11.5px !important; }
            .vedo-confirm-dialog { padding: 18px; border-radius: 14px; }
            .vedo-confirm-actions { flex-direction: column-reverse; }
            .vedo-confirm-actions button { width:100%; }
        }
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after { scroll-behavior: auto !important; animation-duration: .01ms !important; transition-duration: .01ms !important; }
        }
</style>
</head>
<body>

<div class="container">
    <!-- HEADER -->
    <header>
        <div class="header-title-row">
            <a href="?page=dashboard" style="text-decoration:none;color:inherit;"><h1>VEDO MYSQL BACKUP</h1></a>
            <div class="worker-mode-control" title="Yalnızca bir çalışma modu seçilebilir. Sayfa açılışında CLI varsayılandır.">
                <span class="worker-mode-title">Çalışma Modu</span>
                <label class="worker-mode-checkbox" for="workerModeCli">
                    <input type="checkbox" id="workerModeCli" aria-label="CLI modunu kullan" checked>
                    <span>CLI</span>
                </label>
                <label class="worker-mode-checkbox" for="workerModeWeb">
                    <input type="checkbox" id="workerModeWeb" aria-label="Web Worker modunu kullan">
                    <span>WEB</span>
                </label>
                <span id="workerModeStatus" aria-live="polite">CLI seçildi</span>
            </div>
        </div>
        <div class="actions">
            <button class="btn btn-green" id="btnRunBackup" type="button">Şimdi Tam Yedek Al</button>

            <button class="btn btn-secondary" id="btnThemeToggle" type="button" aria-label="Tema değiştir">☾ Koyu Tema</button>
<button class="btn btn-blue" id="btnOpenServerInfo" type="button">Sunucu Bilgisi</button>
            <button class="btn btn-blue" id="btnOpenDbExplorer" type="button">Veritabanı</button>
            <form method="post" action="" style="display:inline; margin:0;">
                <input type="hidden" name="logout" value="1">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">
                <button type="submit" class="btn btn-red" id="btnLogout">Çıkış Yap</button>
            </form>
        </div>
    </header>

    <!-- ÇALIŞMA MODU BİLGİSİ: CLI kullanımının neden önerildiğini CPU kartının hemen üstünde gösterir. -->
    <div class="worker-mode-advice-box" id="workerModeAdvice" aria-live="polite">
        <strong>Öneri:</strong> Yedekleme için CLI modunu kullanmanız daha hızlı ve daha güvenilirdir. WEB modu, CLI kullanılamayan sunucular için alternatif olarak sunulur.
    </div>

    <div class="cron-box cron-box-compact" id="cliCronBox">
        <span class="cron-description">Cron veya zamanlanmış görev ile yedek alabilirsiniz.</span>
        <code class="cron-code-inline" id="cron-command" title="Tam CLI Cron komutunu görmek için Kopyala düğmesini kullanın."><?= htmlspecialchars($cli_cron_command, ENT_QUOTES, 'UTF-8') ?></code>
        <button class="btn btn-blue cron-copy-btn" id="btnCopyCron" type="button">Kopyala</button>
    </div>
<!-- METRİKLER (CPU, RAM, DISK, MySQL, PHP, VERİTABANI) -->
    <div class="grid-metrics">
        <div class="card">
            <div class="card-title">CPU</div>
            <div class="card-value" id="m-cpu-pct">0%</div>
            <div class="card-sub">Load: <span id="m-cpu-load">0.00</span> (<span id="m-cpu-cores">1</span> Çekirdek)</div>
            <div class="progress-bar-bg"><div class="progress-bar-fill" id="m-cpu-bar"></div></div>
        </div>
        <div class="card">
            <div class="card-title">RAM</div>
            <div class="card-value" id="m-ram-pct">0%</div>
            <div class="card-sub"><span id="m-ram-used">0 B</span> / <span id="m-ram-total">0 B</span></div>
            <div class="progress-bar-bg"><div class="progress-bar-fill" id="m-ram-bar"></div></div>
        </div>
        <div class="card">
            <div class="card-title">DISK</div>
            <div class="card-value" id="m-disk-pct">0%</div>
            <div class="card-sub">Boş: <span id="m-disk-free">0 B</span> / <span id="m-disk-total">0 B</span></div>
            <div class="progress-bar-bg"><div class="progress-bar-fill" id="m-disk-bar"></div></div>
        </div>
        <div class="card">
            <div class="card-title">MySQL</div>
            <div class="card-value" id="m-mysql-ver" title="MySQL/MariaDB sürümü">-</div>
            <div class="card-sub">Uptime: <span id="m-uptime">-</span></div>
        </div>
        <div class="card">
            <div class="card-title">PHP</div>
            <div class="card-value" id="m-php-ver" style=" margin-top: 5px;">-</div>
            <div class="card-sub">Limit: <span id="m-php-mem">-</span></div>
        </div>
        <div class="card">
            <div class="card-title">Mevcut Veritabanı</div>
            <div class="card-value" id="m-db-size">0 B</div>
            <div class="card-sub"><span id="m-db-tables">0</span> tablo · <span id="m-db-rows">0</span> satır</div>
        </div>
    </div>

    <!-- CLI CRON: Ayrıntılı açıklama üst satırda, komut ise kısa ve kopyalanabilir alanda gösterilir. -->
    <!-- SUNUCU BİLGİLERİ -->
    <div class="server-info-overlay" id="serverInfoOverlay" aria-hidden="true">
        <div class="server-info-modal" role="dialog" aria-modal="true" aria-labelledby="serverInfoModalTitle">
            <div class="server-info-modal-head">
                <div>
                    <div class="server-info-modal-title" id="serverInfoModalTitle">Sunucu Bilgileri</div>
                    <div class="server-info-modal-subtitle">Sistem, PHP, MySQL, disk, bellek ve veritabanı ayrıntıları</div>
                </div>
                <div class="server-info-head-actions">
                    <button class="btn btn-secondary" id="btnRefreshServerInfo" type="button">Yenile</button>
                    <button class="server-info-close" id="btnCloseServerInfo" type="button" aria-label="Kapat">&times;</button>
                </div>
            </div>
            <div class="server-info-modal-body">
                <div class="server-gauge-grid">
                    <div class="server-gauge-card">
                        <div class="server-gauge" id="serverGaugeCpu" style="--gauge-value:0%;">
                            <div class="server-gauge-inner"><strong id="serverGaugeCpuValue">0%</strong><span>CPU</span></div>
                        </div>
                        <div class="server-gauge-meta" id="serverGaugeCpuMeta">Load: -</div>
                    </div>
                    <div class="server-gauge-card">
                        <div class="server-gauge" id="serverGaugeRam" style="--gauge-value:0%;">
                            <div class="server-gauge-inner"><strong id="serverGaugeRamValue">0%</strong><span>RAM</span></div>
                        </div>
                        <div class="server-gauge-meta" id="serverGaugeRamMeta">-</div>
                    </div>
                    <div class="server-gauge-card">
                        <div class="server-gauge" id="serverGaugeDisk" style="--gauge-value:0%;">
                            <div class="server-gauge-inner"><strong id="serverGaugeDiskValue">0%</strong><span>DISK</span></div>
                        </div>
                        <div class="server-gauge-meta" id="serverGaugeDiskMeta">-</div>
                    </div>
                </div>

                <div class="server-info-grid">
                    <section class="server-info-section">
                        <div class="server-info-section-title">Sunucu</div>
                        <div class="server-info-table" id="serverInfoServerTable"></div>
                    </section>
                    <section class="server-info-section">
                        <div class="server-info-section-title">CPU & Bellek</div>
                        <div class="server-info-table" id="serverInfoResourceTable"></div>
                    </section>
                    <section class="server-info-section">
                        <div class="server-info-section-title">PHP</div>
                        <div class="server-info-table" id="serverInfoPhpTable"></div>
                    </section>
                    <section class="server-info-section">
                        <div class="server-info-section-title">MySQL</div>
                        <div class="server-info-table" id="serverInfoMysqlTable"></div>
                    </section>
                    <section class="server-info-section">
                        <div class="server-info-section-title">Veritabanı</div>
                        <div class="server-info-table" id="serverInfoDbTable"></div>
                    </section>
                    <section class="server-info-section">
                        <div class="server-info-section-title">Yedekleme Alanı</div>
                        <div class="server-info-table" id="serverInfoBackupTable"></div>
                    </section>
                    <section class="server-info-section server-info-full">
                        <div class="server-info-section-title">PHP Uzantıları</div>
                        <div class="server-extension-list" id="serverInfoExtensions"></div>
                    </section>
                </div>
            </div>
        </div>
    </div>

    <div class="db-explorer-overlay" id="dbExplorerOverlay" aria-hidden="true">
        <div class="db-explorer-modal" role="dialog" aria-modal="true" aria-labelledby="dbExplorerModalTitle">
            <div class="db-explorer-modal-head">
                <div>
                    <div class="db-explorer-modal-title" id="dbExplorerModalTitle">Veritabanı Gezgini</div>
                    <div class="db-explorer-modal-subtitle">PHPMyAdmin tarzı tablo görüntüleme ve yönetim paneli</div>
                </div>
                <button class="db-explorer-close" id="btnCloseDbExplorer" type="button" aria-label="Kapat">&times;</button>
            </div>
            <div class="db-explorer-modal-body">
    <!-- PHPMyAdmin TARZI DATABASE EXPLORER -->
    <div class="panel-box" id="dbExplorerPanel">
        <div class="section-title"><span>Veritabanı Gezgini</span><span class="badge badge-success" id="dbNameBadge">-</span></div>
        <div class="db-explorer">
            <aside class="db-sidebar" id="dbTableList"><div style="padding:12px;color:var(--text-secondary);">Tablolar yükleniyor...</div></aside>
            <section class="db-main">
                <div class="db-toolbar">
                    <strong id="dbSelectedTable">Tablo seçin</strong>
                    <button class="btn btn-secondary" id="dbStructureBtn" type="button">Yapı</button>
                    <button class="btn btn-blue" id="dbAnalyzeBtn" type="button">Analiz</button>
                    <button class="btn btn-secondary" id="dbRepairBtn" type="button">Tamir</button>
                    <button class="btn btn-secondary" id="dbOptimizeBtn" type="button">Optimize</button>
                    <button class="btn btn-red" id="dbTruncateBtn" type="button">Boşalt</button>
                    <button class="btn btn-red" id="dbDropBtn" type="button">Sil</button>
                    <button class="btn btn-secondary" id="dbRefreshBtn" type="button">Tabloları Yenile</button>
                    <button class="btn btn-red" id="dbEmptyDatabaseBtn" type="button">Veritabanını Tamamen Temizle</button>
                </div>
                <div id="dbTableMeta" style="color:var(--text-secondary);margin-bottom:10px;">-</div>
                <div class="db-data-wrap" id="dbDataWrap"><div style="padding:20px;color:var(--text-secondary);">Tablo seçildiğinde veriler burada görünecek.</div></div>
                <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:10px;">
                    <button class="btn btn-secondary" id="dbPrevBtn" type="button">‹ Önceki</button>
                    <span id="dbPageInfo" style="padding:8px;color:var(--text-secondary);">0</span>
                    <button class="btn btn-secondary" id="dbNextBtn" type="button">Sonraki ›</button>
                </div>
            </section>
        </div>
    </div>

            </div>
        </div>
    </div>

    <!-- CANLI YEDEKLEME İLERLEME PANELİ -->
    <div class="panel-box" id="live-progress-panel">
        <div class="section-title">
            <span>Canlı Yedekleme İlerlemesi</span>
            <span class="badge badge-warning" id="bg-status-badge">ÇALIŞIYOR</span>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
            <span id="bg-status-text">Yedekleme hazırlanıyor...</span>
            <span id="bg-percent-text" style="">0%</span>
        </div>
        <div class="progress-bar-bg" style="height: 10px;">
            <div class="progress-bar-fill" id="bg-progress-bar" style="width: 0%;"></div>
        </div>
        <div class="progress-info-grid">
            <div class="progress-info-item">
                <span>AKTİF TABLO</span>
                <strong id="bg-active-table">-</strong>
            </div>
            <div class="progress-info-item">
                <span>TABLO SIIRASI</span>
                <strong id="bg-table-idx">0 / 0</strong>
            </div>
            <div class="progress-info-item">
                <span>İŞLENEN SATIR</span>
                <strong id="bg-processed-rows">0</strong>
            </div>
            <div class="progress-info-item">
                <span>HIZ</span>
                <strong id="bg-speed">0 satır/sn</strong>
            </div>
            <div class="progress-info-item">
                <span>GEÇEN SÜRE</span>
                <strong id="bg-elapsed">0s</strong>
            </div>
            <div class="progress-info-item">
                <span>ETA (TAHMİNİ)</span>
                <strong id="bg-eta">0s</strong>
            </div>
            <div class="progress-info-item">
                <span>YAZILAN BOYUT</span>
                <strong id="bg-written-bytes">0 B</strong>
            </div>
        </div>
    </div>

    <!-- MEVCUT YEDEKLER TABLOSU -->
    <div class="panel-box">
        <div class="section-title">
            <span>Mevcut Yedekler</span>

        </div>
        <div class="bulk-backup-toolbar">
            <label class="bulk-select-label">
                <input type="checkbox" id="selectAllBackups">
                <span>Tümünü Seç</span>
            </label>
            <span id="selectedBackupCount">0 yedek seçildi</span>
            <button class="btn btn-red" id="bulkDeleteBackupsBtn" type="button" disabled>Seçilenleri Sil</button>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Dosya Adı</th>
                    <th>Boyut</th>
                    <th>Tarih</th>
                    <th>Bütünlük (SHA256)</th>
                    <th style="text-align: right;">İşlemler</th>
                </tr>
            </thead>
            <tbody id="backups-list">
                <tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">Yükleniyor...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- SİSTEM LOGLARI -->
    <div class="panel-box">
        <div class="section-title">
            <span>Sistem Logları</span>
            <div style="display:flex; gap:6px; align-items:center;">
                <button class="btn btn-secondary" id="btnOpenLogs" type="button" style="padding: 4px 8px;">Logları Büyüt</button>
                <button class="btn btn-secondary" id="btnClearLogs" type="button" style="padding: 4px 8px;">Logları Temizle</button>
            </div>
        </div>
        <div class="log-controls">
            <input type="text" id="logSearch" placeholder="Loglarda ara..." style="flex: 1;">
            <select id="logLevelFilter">
                <option value="ALL">Tüm Seviyeler</option>
                <option value="INFO">INFO</option>
                <option value="WARNING">WARNING</option>
                <option value="ERROR">ERROR</option>
            </select>
        </div>
        <div class="log-box" id="logBoxContainer">Log yükleniyor...</div>
    </div>
</div>

<!-- SİSTEM LOGLARI GENİŞ GÖRÜNÜM -->
<div class="log-modal-overlay" id="logModalOverlay" aria-hidden="true">
    <div class="log-modal" role="dialog" aria-modal="true" aria-labelledby="logModalTitle">
        <div class="log-modal-head">
            <span class="log-modal-title" id="logModalTitle">Sistem Logları</span>
            <button class="btn btn-secondary" id="btnCloseLogs" type="button">Kapat</button>
        </div>
        <div class="log-modal-body">
            <div class="log-box" id="logModalBox">Log yükleniyor...</div>
        </div>
    </div>
</div>

<!-- MODERN CONFIRM MODAL -->
<div class="vedo-confirm-overlay" id="vedoConfirmOverlay" aria-hidden="true">
    <div class="vedo-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="vedoConfirmTitle" aria-describedby="vedoConfirmMessage">
        <h3 class="vedo-confirm-title" id="vedoConfirmTitle">İşlemi onayla</h3>
        <p class="vedo-confirm-message" id="vedoConfirmMessage"></p>
        <div class="vedo-confirm-actions">
            <button type="button" class="btn btn-secondary" id="vedoConfirmCancel">Vazgeç</button>
            <button type="button" class="btn btn-danger" id="vedoConfirmOk">Devam Et</button>
        </div>
    </div>
</div>

<!-- TOAST CONTAINER -->
<div id="toast-container"></div>

<script nonce="<?= $nonce ?>">
    (()=>{
        const key='vedo_theme';
        const root=document.documentElement;
        const saved=localStorage.getItem(key);
        const defaultTheme='<?= $config['ui_default_theme'] === 'light' ? 'light' : 'dark' ?>';
        const dark=saved === 'dark' || (saved !== 'light' && defaultTheme === 'dark');
        root.classList.toggle('theme-dark', dark);
        root.classList.toggle('theme-light', !dark);

        const btn=document.getElementById('btnThemeToggle');
        if(!btn) return;

        const updateThemeButton=()=>{
            const dark=root.classList.contains('theme-dark');
            btn.textContent=dark ? '☀ Açık Tema' : '☾ Koyu Tema';
            btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
        };

        updateThemeButton();
        btn.addEventListener('click',()=>{
            const dark=!root.classList.contains('theme-dark');
            root.classList.toggle('theme-dark', dark);
            root.classList.toggle('theme-light', !dark);
            localStorage.setItem(key, dark ? 'dark' : 'light');
            updateThemeButton();
        });
    })();

    const CSRF_TOKEN = '<?= $_SESSION['csrf_token'] ?>';
    let rawLogLines = [];
    let progressInterval = null;
    let cliJobStartedThisPage = false;
    let dbTables = [];
    let dbSelectedTable = '';
    let dbOffset = 0;
    const DB_PAGE_SIZE = 50;

    // Toast Bildirimi
    function showToast(message, isError = false) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${isError ? 'toast-error' : 'toast-success'}`;
        toast.innerText = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    // Modern modal onay katmanı: browser confirm() yerine kullanılır.
    let vedoConfirmResolver = null;
    function showConfirm(message, title = 'İşlemi onayla', confirmText = 'Devam Et') {
        return new Promise((resolve) => {
            const overlay = document.getElementById('vedoConfirmOverlay');
            const titleEl = document.getElementById('vedoConfirmTitle');
            const messageEl = document.getElementById('vedoConfirmMessage');
            const okBtn = document.getElementById('vedoConfirmOk');
            const cancelBtn = document.getElementById('vedoConfirmCancel');
            if (!overlay || !okBtn || !cancelBtn) return resolve(false);

            vedoConfirmResolver = resolve;
            titleEl.textContent = title;
            messageEl.textContent = message;
            okBtn.textContent = confirmText;
            overlay.classList.add('open');
            overlay.setAttribute('aria-hidden', 'false');
            document.body.classList.add('db-modal-open');
            setTimeout(() => okBtn.focus(), 0);
        });
    }

    function closeConfirm(result = false) {
        const overlay = document.getElementById('vedoConfirmOverlay');
        if (overlay) {
            overlay.classList.remove('open');
            overlay.setAttribute('aria-hidden', 'true');
        }
        document.body.classList.remove('db-modal-open');
        if (typeof vedoConfirmResolver === 'function') {
            const resolve = vedoConfirmResolver;
            vedoConfirmResolver = null;
            resolve(result);
        }
    }

    document.getElementById('vedoConfirmOk')?.addEventListener('click', () => closeConfirm(true));
    document.getElementById('vedoConfirmCancel')?.addEventListener('click', () => closeConfirm(false));
    document.getElementById('vedoConfirmOverlay')?.addEventListener('click', (e) => {
        if (e.target.id === 'vedoConfirmOverlay') closeConfirm(false);
    });

    // XSS Escape Helper
    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Merkezi API isteği.
    async function apiRequest(action, data = {}, usePost = true) {
        const body = new URLSearchParams();
        body.append('csrf_token', CSRF_TOKEN);

        for (const [key, value] of Object.entries(data)) {
            body.append(key, value);
        }

        const url = `?action=${encodeURIComponent(action)}`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);

        let response;
        try {
            response = await fetch(url, {
                method: usePost ? 'POST' : 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-CSRF-TOKEN': CSRF_TOKEN,
                    'Accept': 'application/json'
                },
                body: usePost ? body.toString() : undefined,
                signal: controller.signal
            });
        } catch (fetchError) {
            if (fetchError?.name === 'AbortError') {
                throw new Error('Sunucu isteği zaman aşımına uğradı.');
            }
            throw fetchError;
        } finally {
            clearTimeout(timeoutId);
        }

        const text = await response.text();
        let json;

        try {
            json = JSON.parse(text);
        } catch (e) {
            console.error('API JSON HATASI:', text);
            throw new Error(`Sunucudan geçersiz JSON yanıtı geldi (HTTP ${response.status}).`);
        }

        if (!json.success) {
            throw new Error(json.message || `İşlem başarısız (HTTP ${response.status}).`);
        }

        return json;
    }

    // Load Dashboard Data
    // DASHBOARD: sunucu, veritabanı, yedek ve log bilgilerini yeniler
    async function loadDashboard() {
        try {
            const res = await apiRequest('get_dashboard_data', {}, false);
            const m = res.data.metrics;
            const files = res.data.files;
            rawLogLines = res.data.logs || [];
            renderServerInfo(m);

            // Metrik bilgilerini güncelle
            document.getElementById('m-cpu-pct').innerText = m.cpu.percent + '%';
            document.getElementById('m-cpu-load').innerText = m.cpu.load_1min;
            document.getElementById('m-cpu-cores').innerText = m.cpu.cores;
            document.getElementById('m-cpu-bar').style.width = m.cpu.percent + '%';

            document.getElementById('m-ram-pct').innerText = m.ram.percent + '%';
            document.getElementById('m-ram-used').innerText = formatBytes(m.ram.used);
            document.getElementById('m-ram-total').innerText = formatBytes(m.ram.total);
            document.getElementById('m-ram-bar').style.width = m.ram.percent + '%';

            document.getElementById('m-disk-pct').innerText = m.disk.percent + '%';
            document.getElementById('m-disk-free').innerText = formatBytes(m.disk.free);
            document.getElementById('m-disk-total').innerText = formatBytes(m.disk.total);
            document.getElementById('m-disk-bar').style.width = m.disk.percent + '%';

            document.getElementById('m-mysql-ver').innerText = m.mysql_version;
            document.getElementById('m-uptime').innerText = m.uptime;

            document.getElementById('m-php-ver').innerText = m.php_version;
            document.getElementById('m-php-mem').innerText = m.php_env.memory_limit;

            document.getElementById('m-db-size').innerText = m.database.formatted_size;
            document.getElementById('m-db-tables').innerText = m.database.table_count.toLocaleString('tr-TR');
            document.getElementById('m-db-rows').innerText = m.database.total_rows.toLocaleString('tr-TR');
            // Render Files
            renderBackupTable(files);

            // Render Logs
            filterLogs();

        } catch (err) {
            showToast('Dashboard yüklenirken hata: ' + err.message, true);
        }
    }
    function getPersistedBackupSelection() {
        try {
            const raw = sessionStorage.getItem('vedo_backup_selection');
            const arr = raw ? JSON.parse(raw) : [];
            return new Set(Array.isArray(arr) ? arr : []);
        } catch (e) {
            return new Set();
        }
    }
    function persistBackupSelection() {
        try {
            sessionStorage.setItem('vedo_backup_selection', JSON.stringify(getSelectedBackupFiles()));
        } catch (e) {}
    }
    function getSelectedBackupFiles() {
        return Array.from(document.querySelectorAll('#backups-list .backup-select:checked'))
            .map(el => el.value || el.closest('tr')?.dataset.file || '')
            .filter(Boolean);
    }
    function updateBackupSelectionUI() {
        const boxes = Array.from(document.querySelectorAll('#backups-list .backup-select'));
        const selected = boxes.filter(el => el.checked);
        const count = document.getElementById('selectedBackupCount');
        const btn = document.getElementById('bulkDeleteBackupsBtn');
        const master = document.getElementById('selectAllBackups');

        if (count) count.textContent = `${selected.length} yedek seçildi`;
        if (btn) btn.disabled = selected.length === 0;
        if (master) {
            master.checked = boxes.length > 0 && selected.length === boxes.length;
            master.indeterminate = selected.length > 0 && selected.length < boxes.length;
        }
        persistBackupSelection();
    }
    function restoreBackupSelection() {
        const saved = getPersistedBackupSelection();
        document.querySelectorAll('#backups-list .backup-select').forEach(cb => {
            cb.checked = saved.has(cb.value || cb.closest('tr')?.dataset.file || '');
        });
        updateBackupSelectionUI();
    }

    async function bulkDeleteBackups() {
        const files = getSelectedBackupFiles();
        if (!files.length) {
            showToast('Önce en az bir yedek seçin.', true);
            return;
        }

        const confirmed = await showConfirm(
            `${files.length} yedek dosyası kalıcı olarak silinecek. Bu işlem geri alınamaz.`,
            'Seçili yedekleri sil',
            'Evet, hepsini sil'
        );
        if (!confirmed) return;

        const btn = document.getElementById('bulkDeleteBackupsBtn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = `Siliniyor (${files.length})...`;
        }

        try {
            const body = new URLSearchParams();
            body.set('csrf_token', CSRF_TOKEN);
            body.set('files', JSON.stringify(files));

            const response = await fetch('?action=bulk_delete_backups', {
                method:'POST',
                credentials:'same-origin',
                headers:{
                    'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-CSRF-TOKEN':CSRF_TOKEN,
                    'Accept':'application/json'
                },
                body:body.toString()
            });

            const raw=await response.text();
            let json;
            try {
                json=JSON.parse(raw);
            } catch (e) {
                console.error('Toplu silme ham sunucu cevabı:', raw);
                throw new Error(`Sunucu JSON yerine HTTP ${response.status} cevabı döndürdü.`);
            }

            const deleted=Number(json.data?.deleted || 0);
            const failed=Array.isArray(json.data?.failed) ? json.data.failed : [];

            if (!json.success && deleted === 0) {
                throw new Error(json.message || 'Toplu silme başarısız.');
            }

            const saved=getPersistedBackupSelection();
            (json.data?.deleted_files || files).forEach(file=>saved.delete(file));
            sessionStorage.setItem('vedo_backup_selection',JSON.stringify([...saved]));

            showToast(
                failed.length
                    ? `${deleted} yedek silindi, ${failed.length} yedek silinemedi.`
                    : `${deleted} yedek başarıyla silindi.`,
                failed.length>0
            );

            await loadDashboard();
            restoreBackupSelection();
        } catch(e) {
            console.error('Toplu yedek silme:',e);
            showToast('Toplu silme hatası: '+e.message,true);
        } finally {
            if(btn){
                btn.disabled=false;
                btn.textContent='Seçilenleri Sil';
            }
            updateBackupSelectionUI();
        }
    }
    async function emptyEntireDatabase() {
        const confirmed = await showConfirm(
            'Veritabanındaki tabloların verileri boşaltılacak. Bu işlem geri alınamaz.',
            'Veritabanını boşalt',
            'Evet, boşalt'
        );
        if (!confirmed) return;

        const btn = document.getElementById('dbEmptyDatabaseBtn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Boşaltılıyor...';
        }

        try {
            // API katmanı CSRF tokenını otomatik ekler ve JSON cevabını doğrular.
            const result = await apiRequest('empty_database');

            const emptied = Number(result.data?.emptied ?? result.data?.tables ?? 0);
            const failed = Array.isArray(result.data?.failed) ? result.data.failed : [];

            if (failed.length > 0) {
                showToast(
                    `${emptied} tablo boşaltıldı, ${failed.length} tablo boşaltılamadı.`,
                    true
                );
            } else {
                showToast(result.message || `${emptied} tablo boşaltıldı.`);
            }

            // Veritabanı tamamen temizlendiyse gezginin eski seçimini ve sayfa bilgisini sıfırla.
            dbSelectedTable = '';
            dbOffset = 0;
            const dbSelectedLabel = document.getElementById('dbSelectedTable');
            const dbDataWrap = document.getElementById('dbDataWrap');
            const dbPageInfo = document.getElementById('dbPageInfo');
            if (dbSelectedLabel) dbSelectedLabel.innerText = '-';
            if (dbDataWrap) dbDataWrap.innerHTML = '<div style="padding:20px;color:var(--text-secondary);">Veritabanında tablo bulunmuyor.</div>';
            if (dbPageInfo) dbPageInfo.innerText = '0-0';

            // Veritabanı gezginindeki eski kayıtları yeniden yükle.
            if (typeof loadDatabaseTables === 'function') {
                await loadDatabaseTables(false);
            }

            if (typeof loadDashboard === 'function') {
                await loadDashboard();
            }

        } catch (e) {
            console.error('Veritabanı boşaltma:', e);
            showToast('Veritabanı boşaltma hatası: ' + e.message, true);
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Veritabanını Tamamen Temizle';
            }
        }
    }
    function renderBackupTable(files) {
        const tbody = document.getElementById('backups-list');
        if (!files || files.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">Henüz oluşturulmuş yedek bulunmuyor.</td></tr>';
            return;
        }

        tbody.innerHTML = files.map(f => `
            <tr data-backup-row="${escapeHtml(f.name)}" data-file="${escapeHtml(f.name)}">
                <td class="backup-file-cell">
                    <label class="backup-checkbox-label">
                        <input type="checkbox" class="backup-select" value="${escapeHtml(f.name)}" aria-label="Yedeği seç">
                        <strong>${escapeHtml(f.name)}</strong>
                    </label>
                </td>
                <td>${escapeHtml(f.size)}</td>
                <td>${escapeHtml(f.mtime)}</td>
                <td>
                    ${f.has_sha256
                        ? '<span class="badge badge-success">Mevcut (SHA256)</span>'
                        : '<span class="badge badge-warning">İmza Yok</span>'}
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-blue" style="padding: 4px 8px;" data-action="download" data-file="${escapeHtml(f.name)}">İndir</button>
                    <button class="btn btn-secondary" style="padding: 4px 8px;" data-action="verify" data-file="${escapeHtml(f.name)}">Doğrula</button>
                    <button class="btn btn-green" style="padding: 4px 8px;" data-action="restore" data-file="${escapeHtml(f.name)}">Restore</button>
                    <button class="btn btn-red" style="padding: 4px 8px;" data-action="delete" data-file="${escapeHtml(f.name)}">Sil</button>
                </td>
            </tr>
        `).join('');
        restoreBackupSelection();
    }
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function loadDatabaseTables(selectFirst = true) {
        logClientAction('Veritabanı tabloları görüntülendi');
        try {
            const res = await apiRequest('db_tables', {}, false);
            dbTables = res.data.tables || [];
            document.getElementById('dbNameBadge').innerText = res.data.database || '-';
            const list = document.getElementById('dbTableList');
            if (!dbTables.length) { list.innerHTML = '<div style="padding:12px;color:var(--text-secondary);">Tablo bulunamadı.</div>'; return; }
            list.innerHTML = dbTables.map(t => `<div class="db-table-item ${t.TABLE_NAME===dbSelectedTable?'active':''}" data-db-table="${escapeHtml(t.TABLE_NAME)}"><span>${escapeHtml(t.TABLE_NAME)}</span><small>${Number(t.TABLE_ROWS||0).toLocaleString()}</small></div>`).join('');
            if (selectFirst && !dbSelectedTable) dbSelectedTable = dbTables[0].TABLE_NAME;
            if (dbSelectedTable) await selectDatabaseTable(dbSelectedTable);
        } catch (e) { showToast('Tablolar yüklenemedi: ' + e.message, true); }
    }

    async function selectDatabaseTable(table) {
        dbSelectedTable = table; dbOffset = 0;
        document.getElementById('dbSelectedTable').innerText = table;
        document.querySelectorAll('[data-db-table]').forEach(el => el.classList.toggle('active', el.dataset.dbTable === table));
        await loadDatabaseTableData();
    }

    async function loadDatabaseTableData() {
        if (!dbSelectedTable) return;
        try {
            const res = await apiRequest('db_table_data', {table: dbSelectedTable, limit: DB_PAGE_SIZE, offset: dbOffset});
            const rows = res.data.rows || [];
            const meta = dbTables.find(t => t.TABLE_NAME === dbSelectedTable);
            document.getElementById('dbTableMeta').innerText = meta ? `${meta.TABLE_TYPE} • ${meta.ENGINE || 'N/A'} • ${Number(meta.TABLE_ROWS||0).toLocaleString()} satır • ${meta.FORMATTED_SIZE}` : '';
            const wrap = document.getElementById('dbDataWrap');
            if (!rows.length) { wrap.innerHTML = '<div style="padding:20px;color:var(--text-secondary);">Bu sayfada veri yok.</div>'; }
            else {
                const cols = Object.keys(rows[0]);
                wrap.innerHTML = `<table><thead><tr>${cols.map(c=>`<th>${escapeHtml(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${cols.map(c=>`<td title="${escapeHtml(r[c] ?? '')}">${escapeHtml(r[c] ?? 'NULL')}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
            }
            document.getElementById('dbPageInfo').innerText = `${dbOffset + 1}-${dbOffset + rows.length}`;
            document.getElementById('dbPrevBtn').disabled = dbOffset === 0;
            document.getElementById('dbNextBtn').disabled = rows.length < DB_PAGE_SIZE;
        } catch (e) { showToast('Tablo verisi yüklenemedi: ' + e.message, true); }
    }

    async function loadDatabaseStructure() {
        if (!dbSelectedTable) return showToast('Önce tablo seç.', true);
        try {
            const res = await apiRequest('db_table_structure', {table: dbSelectedTable});
            const cols = res.data.columns || [];
            document.getElementById('dbDataWrap').innerHTML = `<table><thead><tr><th>Kolon</th><th>Tip</th><th>Null</th><th>Key</th><th>Default</th><th>Extra</th></tr></thead><tbody>${cols.map(c=>`<tr><td>${escapeHtml(c.COLUMN_NAME)}</td><td>${escapeHtml(c.COLUMN_TYPE)}</td><td>${escapeHtml(c.IS_NULLABLE)}</td><td>${escapeHtml(c.COLUMN_KEY||'')}</td><td>${escapeHtml(c.COLUMN_DEFAULT ?? 'NULL')}</td><td>${escapeHtml(c.EXTRA||'')}</td></tr>`).join('')}</tbody></table>`;
        } catch(e) { showToast('Yapı alınamadı: '+e.message,true); }
    }

    async function dbMaintenance(operation) {
        if (!dbSelectedTable) return showToast('Önce tablo seç.', true);
        try { const res = await apiRequest('db_table_maintenance',{table:dbSelectedTable,operation}); showToast(res.data?.message || res.message); loadDatabaseTables(false); }
        catch(e){ showToast('Bakım hatası: '+e.message,true); }
    }

    async function dbDestructive(operation) {
        if (!dbSelectedTable) return showToast('Önce tablo seç.', true);
        const table = dbSelectedTable;
        const actionText = operation === 'truncate' ? 'tablonun tüm verileri silinecek' : 'tablo kalıcı olarak silinecek';
        const confirmed = await showConfirm(
            `“${table}” seçildi. ${actionText}. Bu işlem geri alınamaz.`,
            operation === 'truncate' ? 'Tabloyu boşalt' : 'Tabloyu sil',
            operation === 'truncate' ? 'Evet, boşalt' : 'Evet, sil'
        );
        if (!confirmed) return;
        try {
            await apiRequest(operation === 'truncate' ? 'db_table_truncate' : 'db_table_drop', {table});
            showToast(operation === 'truncate' ? 'Tablo boşaltıldı.' : 'Tablo silindi.');
            if (operation === 'drop') dbSelectedTable = '';
            await loadDatabaseTables(true);
        } catch (e) {
            showToast('İşlem hatası: ' + e.message, true);
        }
    }
    function copyCronCommand() {
        const code = document.getElementById('cron-command');
        if (!code) return;

        const command = code.textContent.trim();

        navigator.clipboard?.writeText(command).then(() => {
            showToast('CLI Cron komutu kopyalandı.');
        }).catch(() => {
            const range = document.createRange();
            range.selectNodeContents(code);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);

            try {
                document.execCommand('copy');
                showToast('CLI Cron komutu kopyalandı.');
            } catch (e) {
                showToast('CLI Cron komutu kopyalanamadı.', true);
            }

            selection.removeAllRanges();
        });
    }

    // Sayfa her açıldığında CLI işaretlidir. Kullanıcı isterse WEB'i seçebilir.
    function getWorkerMode() {
        const cliCheckbox = document.getElementById('workerModeCli');
        const webCheckbox = document.getElementById('workerModeWeb');
        return webCheckbox?.checked ? 'web' : 'cli';
    }
    function setWorkerMode(mode) {
        const cliCheckbox = document.getElementById('workerModeCli');
        const webCheckbox = document.getElementById('workerModeWeb');
        if (!cliCheckbox || !webCheckbox) return;

        if (mode === 'web') {
            webCheckbox.checked = true;
            cliCheckbox.checked = false;
        } else {
            cliCheckbox.checked = true;
            webCheckbox.checked = false;
        }
    }

    function updateWorkerModeStatus(modeOverride = '') {
        const mode = modeOverride || getWorkerMode();
        setWorkerMode(mode);
        const status = document.getElementById('workerModeStatus');
        if (status) status.textContent = mode === 'web' ? 'Web Worker seçildi' : 'CLI seçildi';

        // CLI modu seçiliyken Cron komutu görünür; WEB modunda kullanıcıyı şaşırtmaması için gizlenir.
        const cronBox = document.getElementById('cliCronBox');
        if (cronBox) cronBox.style.display = mode === 'web' ? 'none' : '';

        // Çalışma modu tavsiyesini de seçime göre günceller.
        const advice = document.getElementById('workerModeAdvice');
        if (advice) {
            advice.innerHTML = mode === 'web'
                ? '<strong>Bilgi:</strong> WEB Worker seçildi. Sayfa açık kalmalıdır; CLI kullanabiliyorsanız CLI modu önerilir.'
                : '<strong>Öneri:</strong> Yedekleme için CLI modunu kullanmanız daha hızlı ve daha güvenilirdir. WEB modu, CLI kullanılamayan sunucular için alternatif olarak sunulur.';
        }
    }

    document.getElementById('workerModeCli')?.addEventListener('change', function () {
        updateWorkerModeStatus('cli');
        void logClientAction('Çalışma modu seçildi', 'mod=CLI');
    });
    document.getElementById('workerModeWeb')?.addEventListener('change', function () {
        updateWorkerModeStatus('web');
        void logClientAction('Çalışma modu seçildi', 'mod=WEB_WORKER');
    });
    // İlk açılışta CLI varsayılan ve tek seçili moddur.
    updateWorkerModeStatus('cli');

    // Tam yedekleme.
    let activeCliJobId = '';

    async function startFullBackup() {
        const workerMode = getWorkerMode();
        logClientAction('Yedekleme başlatıldı', 'mod=' + workerMode.toUpperCase());
        try {
            document.getElementById('live-progress-panel').style.display = 'block';
            showToast('Yedekleme işlemi başlatılıyor...');
            cliJobStartedThisPage = true;
            const res = await apiRequest('run_full_backup', { worker_mode: workerMode });
            activeCliJobId = res?.data?.job_id || '';
            if (!activeCliJobId) throw new Error('Worker job ID alınamadı.');
            startProgressPolling();
            showToast(res?.data?.engine === 'web' ? 'Web Worker yedekleme başlatıldı. Sayfayı açık tut.' : 'CLI yedekleme başlatıldı. Sayfayı kapatsan bile işlem devam eder.');
        } catch (err) {
            const errorMessage = err?.message || String(err);
            showToast('Yedekleme Hatası: ' + errorMessage, true);
            try {
                await apiRequest('client_activity_log', {
                    action_name: 'Yedekleme hatası',
                    details: errorMessage
                });
            } catch (logErr) {
                console.error('Hata loglanamadı:', logErr);
            }
            stopProgressPolling();
        }
    }

    // Live Progress Polling
    function startProgressPolling() {
        stopProgressPolling();
        const poll = async () => {
            if (!activeCliJobId) {
                progressInterval = null;
                return;
            }
            await fetchProgress();
            if (activeCliJobId) {
                progressInterval = setTimeout(poll, 700);
            } else {
                progressInterval = null;
            }
        };
        progressInterval = setTimeout(poll, 0);
    }
    function stopProgressPolling() {
        if (progressInterval) {
            clearTimeout(progressInterval);
            progressInterval = null;
        }
    }

    async function fetchProgress() {
        try {
            let d = null;

            if (!activeCliJobId) return;

            const res = await apiRequest('get_cli_job_progress', { job_id: activeCliJobId });
            d = res.data;

            if (!d || d.status === 'idle') return;

            document.getElementById('live-progress-panel').style.display = 'block';
            document.getElementById('bg-status-text').innerText =
                d.current_table ? `İşleniyor: ${d.current_table}` :

                d.status === 'failed' ? (d.error || 'İşlem başarısız.') :
                (d.engine === 'web' ? 'Web Worker çalışıyor...' : 'CLI işlem çalışıyor...');
            document.getElementById('bg-percent-text').innerText = (d.percent || 0) + '%';
            document.getElementById('bg-progress-bar').style.width = (d.percent || 0) + '%';

            document.getElementById('bg-active-table').innerText = d.current_table || d.file || '-';
            document.getElementById('bg-table-idx').innerText = d.total_tables ? `${d.current_table_index || 0} / ${d.total_tables}` : '-';
            document.getElementById('bg-processed-rows').innerText = (d.processed_rows || d.rows_count || 0).toLocaleString();
            document.getElementById('bg-speed').innerText = d.speed_mb_per_second
                ? `${d.speed_mb_per_second} MB/sn`
                : `${(d.speed_rows_per_second || 0).toLocaleString()} satır/sn`;
            document.getElementById('bg-elapsed').innerText = `${d.elapsed_seconds || d.duration_seconds || 0}s`;
            document.getElementById('bg-eta').innerText = `${d.estimated_remaining_seconds || 0}s`;
            document.getElementById('bg-written-bytes').innerText =
                d.formatted_bytes || d.formatted_processed || (d.size ? formatBytes(d.size) : '0 B');

            const badge = document.getElementById('bg-status-badge');
            if (d.status === 'completed') {
                // İşlem tamamlandığında son tablo adı yerine kesin olarak tamamlandı mesajı göster.
                document.getElementById('bg-status-text').innerText = 'Restore tamamlandı';
                badge.className = 'badge badge-success';
                badge.innerText = 'TAMAMLANDI';
                stopProgressPolling();
                activeCliJobId = '';
                loadDashboard();

            } else if (d.status === 'failed') {
                badge.className = 'badge badge-danger';
                badge.innerText = 'HATA';
                stopProgressPolling();
                const cliError = 'İşlem hatası: ' + (d.error || 'Bilinmeyen hata');
                showToast(cliError, true);
                try {
                    if (activeCliJobId && window.__lastCliErrorLogged !== activeCliJobId + '|' + cliError) {
                        window.__lastCliErrorLogged = activeCliJobId + '|' + cliError;
                        await apiRequest('client_activity_log', {
                            action_name: 'CLI job hatası',
                            details: cliError
                        });
                    }
                } catch (logErr) {
                    console.error('CLI hata logu yazılamadı:', logErr);
                }
                activeCliJobId = '';
            } else {
                badge.className = 'badge badge-warning';
                badge.innerText = (d.engine === 'web' ? 'WEB WORKER' : 'CLI ÇALIŞIYOR');
            }
        } catch (e) {
            // Sessizce geçilebilir
        }
    }

    // Download File
    async function downloadFile(file) {
        logClientAction('Yedek indirildi', String(file || ''));
        try {
            const body = new URLSearchParams();
            body.append('csrf_token', CSRF_TOKEN);
            body.append('file', String(file || ''));
            const response = await fetch('?action=download_backup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-TOKEN': CSRF_TOKEN
                },
                body: body.toString()
            });
            if (!response.ok) {
                const text = await response.text();
                let message = `İndirme başarısız (HTTP ${response.status}).`;
                try {
                    const json = JSON.parse(text);
                    message = json.message || message;
                } catch (_) {}
                throw new Error(message);
            }
            const blob = await response.blob();
            const disposition = response.headers.get('Content-Disposition') || '';
            const match = disposition.match(/filename=\"?([^\";]+)\"?/i);
            const filename = match ? match[1] : String(file || 'backup.sql.gz');
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (err) {
            showToast('İndirme hatası: ' + err.message, true);
        }
    }

    async function deleteFile(file) {
        const confirmed = await showConfirm(
            `“${file}” yedek dosyası kalıcı olarak silinecek.`,
            'Yedeği sil',
            'Evet, sil'
        );
        if (!confirmed) return;

        logClientAction('Yedek silindi', String(file || ''));
        try {
            await apiRequest('delete_backup', { file: file });
            showToast('Yedek dosyası silindi.');
            loadDashboard();
        } catch (err) {
            showToast('Silme hatası: ' + err.message, true);
        }
    }

    async function verifyFile(file) {
        logClientAction('Yedek bütünlük kontrolü', String(file || ''));
        showToast(`'${file}' için SHA256 bütünlük doğrulaması hesaplanıyor...`);
        try {
            const res = await apiRequest('check_integrity', { file: file });
            showToast(`BAŞARILI: ${res.message}`);
            loadDashboard();
        } catch (err) {
            showToast('Bütünlük Hatası: ' + err.message, true);
        }
    }

    // RESTORE: seçilen yedekten geri yükleme işlemini başlatır
    async function triggerRestore(file) {
        const workerMode = getWorkerMode();
        logClientAction('Restore başlatıldı', String(file || '') + ' | mod=' + workerMode.toUpperCase());
        if (!file || typeof file !== 'string') {
            showToast('Geri yüklenecek yedek dosyası bulunamadı.', true);
            return;
        }

        const confirmed = await showConfirm(
            `“${file}” yedeği veritabanına geri yüklenecek. Mevcut veriler etkilenebilir.`,
            'Restore işlemini başlat',
            'Restore başlat'
        );
        if (!confirmed) return;

        document.getElementById('live-progress-panel').style.display = 'block';
        showToast(`'${file}' restore işlemi başlatılıyor...`);
        cliJobStartedThisPage = true;

        try {
            const res = await apiRequest('restore_chunk', { file: file, worker_mode: workerMode });
            activeCliJobId = res?.data?.job_id || '';
            if (!activeCliJobId) throw new Error('Worker restore job ID alınamadı.');
            startProgressPolling();
            showToast(res?.data?.engine === 'web' ? 'Web Worker restore başladı. Sayfayı açık tut.' : 'CLI restore başladı. Sayfayı kapatsan bile restore devam eder.');
        } catch (err) {
            const errorMessage = err?.message || String(err);
            showToast('Restore Hatası: ' + errorMessage, true);
            try {
                await apiRequest('client_activity_log', {
                    action_name: 'Restore hatası',
                    details: errorMessage
                });
            } catch (logErr) {
                console.error('Restore hata logu yazılamadı:', logErr);
            }
            stopProgressPolling();
            activeCliJobId = '';
        }
    }

    // Logs System
    function hasLogSelection(element) {
        if (!element || !window.getSelection) return false;
        const selection = window.getSelection();
        if (!selection || selection.isCollapsed || selection.rangeCount === 0) return false;
        const anchor = selection.anchorNode;
        const focus = selection.focusNode;
        return !!((anchor && element.contains(anchor)) || (focus && element.contains(focus)));
    }
    function renderLogBoxes(html) {
        const logBox = document.getElementById('logBoxContainer');
        const modalBox = document.getElementById('logModalBox');
        if (!logBox) return;

        // Kullanıcı mavi seçim yapıyorsa innerHTML değiştirilmez; aksi halde seçim anında kaybolur.
        if (hasLogSelection(logBox) || hasLogSelection(modalBox)) return;

        const logScrollTop = logBox.scrollTop;
        const modalScrollTop = modalBox ? modalBox.scrollTop : 0;

        // İçerik değişmediyse DOM'yi hiç yeniden oluşturma.
        if (logBox.innerHTML === html && (!modalBox || modalBox.innerHTML === html)) return;

        logBox.innerHTML = html;
        // Yeni işlem sonrası en son log satırını göster.
        // Periyodik yenileme yok; kullanıcı logu rahatça seçip kopyalayabilir.
        logBox.scrollTop = logBox.scrollHeight;

        if (modalBox) {
            modalBox.innerHTML = html;
            modalBox.scrollTop = modalBox.scrollHeight;
        }
    }

    // Logs System
    function filterLogs() {
        const search = document.getElementById('logSearch').value.toLowerCase();
        const level = document.getElementById('logLevelFilter').value;
        const logBox = document.getElementById('logBoxContainer');

        if (!rawLogLines || rawLogLines.length === 0) {
            if (!hasLogSelection(logBox)) logBox.innerText = 'Henüz log kaydı yok.';
            const modalBox = document.getElementById('logModalBox');
            if (modalBox && !hasLogSelection(modalBox)) modalBox.innerText = 'Henüz log kaydı yok.';
            return;
        }

        const filtered = rawLogLines.filter(line => {
            const matchesSearch = line.toLowerCase().includes(search);
            const matchesLevel = (level === 'ALL') || line.includes(`[${level}]`);
            return matchesSearch && matchesLevel;
        });

        if (filtered.length === 0) {
            if (!hasLogSelection(logBox)) logBox.innerText = 'Filtrelere uygun log bulunamadı.';
            const modalBox = document.getElementById('logModalBox');
            if (modalBox && !hasLogSelection(modalBox)) modalBox.innerText = 'Filtrelere uygun log bulunamadı.';
            return;
        }

        const html = filtered.map(line => {
            let cls = '';
            if (line.includes('[INFO]')) cls = 'log-line-INFO';
            else if (line.includes('[WARNING]')) cls = 'log-line-WARNING';
            else if (line.includes('[ERROR]')) cls = 'log-line-ERROR';
            return `<div class="${cls}">${escapeHtml(line)}</div>`;
        }).join('');

        renderLogBoxes(html);
    }
    async function clearLogs() {
        try {
            await apiRequest('clear_logs', {});
            showToast('Loglar temizlendi.');
            loadDashboard();
        } catch (err) {
            showToast('Log temizleme hatası: ' + err.message, true);
        }
    }

    // CSP uyumlu olay bağlama: inline onclick kullanılmaz.
    async function logClientAction(action, details = '') {
        try {
            const body = new URLSearchParams();
            body.append('csrf_token', CSRF_TOKEN);
            body.append('action_name', action);
            body.append('details', details);

            await fetch('?action=client_activity_log', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-CSRF-TOKEN': CSRF_TOKEN,
                    'Accept': 'application/json'
                },
                body: body.toString(),
                keepalive: true
            });
        } catch (e) {
        }
    }

    let latestServerMetrics = null;

    function setServerGauge(id, value, valueId, metaId, metaText) {
        const pct = Math.max(0, Math.min(100, Number(value) || 0));
        const gauge = document.getElementById(id);
        const valueEl = document.getElementById(valueId);
        const metaEl = document.getElementById(metaId);
        if (gauge) gauge.style.setProperty('--gauge-value', pct + '%');
        if (valueEl) valueEl.textContent = Math.round(pct) + '%';
        if (metaEl) metaEl.textContent = metaText || '';
    }

    function renderServerInfoTable(id, entries) {
        const el = document.getElementById(id);
        if (!el) return;
        el.innerHTML = entries.map(([key, value]) =>
            `<div class="server-info-row"><div class="server-info-key">${escapeHtml(key)}</div><div class="server-info-value">${escapeHtml(value ?? 'N/A')}</div></div>`
        ).join('');
    }

    function refreshOpenServerInfoResources() {
        if (!latestServerMetrics) return;

        const m = latestServerMetrics;
        renderServerInfoTable('serverInfoResourceTable', [
            ['CPU Çekirdeği', m.cpu?.cores],
            ['Load 1 dk', m.cpu?.load_1min],
            ['Load 5 dk', m.cpu?.load_5min],
            ['Load 15 dk', m.cpu?.load_15min],
            ['CPU Kullanımı', (m.cpu?.percent ?? 0) + '%'],
            ['RAM Toplam', formatBytes(m.ram?.total || 0)],
            ['RAM Kullanılan', formatBytes(m.ram?.used || 0)],
            ['RAM Boş / Available', formatBytes(m.ram?.free || 0)],
            ['RAM Kullanımı', (m.ram?.percent ?? 0) + '%'],
            ['Disk Toplam', formatBytes(m.disk?.total || 0)],
            ['Disk Kullanılan', formatBytes(m.disk?.used || 0)],
            ['Disk Boş', formatBytes(m.disk?.free || 0)],
            ['Disk Kullanımı', (m.disk?.percent ?? 0) + '%'],
        ]);
    }

    function renderServerInfo(metrics) {
        if (!metrics) return;
        latestServerMetrics = metrics;

        setServerGauge('serverGaugeCpu', metrics.cpu?.percent, 'serverGaugeCpuValue', 'serverGaugeCpuMeta',
            `Load ${metrics.cpu?.load_1min ?? '-'} · ${metrics.cpu?.cores ?? '-'} çekirdek`);
        setServerGauge('serverGaugeRam', metrics.ram?.percent, 'serverGaugeRamValue', 'serverGaugeRamMeta',
            `${formatBytes(metrics.ram?.used || 0)} / ${formatBytes(metrics.ram?.total || 0)}`);
        setServerGauge('serverGaugeDisk', metrics.disk?.percent, 'serverGaugeDiskValue', 'serverGaugeDiskMeta',
            `${formatBytes(metrics.disk?.used || 0)} / ${formatBytes(metrics.disk?.total || 0)}`);

        renderServerInfoTable('serverInfoServerTable', [
            ['Hostname', metrics.server?.hostname || metrics.hostname],
            ['İşletim Sistemi', metrics.os],
            ['Kernel', metrics.server?.kernel],
            ['Makine', metrics.server?.machine],
            ['Server Software', metrics.server?.server_software],
            ['Server Protocol', metrics.server?.server_protocol],
            ['HTTPS', metrics.server?.https],
            ['Sunucu IP', metrics.server?.server_ip],
            ['İstemci IP', metrics.server?.remote_ip],
            ['Document Root', metrics.server?.document_root],
            ['Script', metrics.server?.script_path],
            ['Yedek Dizini', metrics.server?.disk_path],
            ['Saat Dilimi', metrics.server?.timezone],
            ['Sunucu Saati', metrics.server?.current_time],
        ]);

        renderServerInfoTable('serverInfoResourceTable', [
            ['CPU Çekirdeği', metrics.cpu?.cores],
            ['Load 1 dk', metrics.cpu?.load_1min],
            ['Load 5 dk', metrics.cpu?.load_5min],
            ['Load 15 dk', metrics.cpu?.load_15min],
            ['CPU Kullanımı', (metrics.cpu?.percent ?? 0) + '%'],
            ['RAM Toplam', formatBytes(metrics.ram?.total || 0)],
            ['RAM Kullanılan', formatBytes(metrics.ram?.used || 0)],
            ['RAM Boş / Available', formatBytes(metrics.ram?.free || 0)],
            ['RAM Kullanımı', (metrics.ram?.percent ?? 0) + '%'],
            ['Disk Toplam', formatBytes(metrics.disk?.total || 0)],
            ['Disk Kullanılan', formatBytes(metrics.disk?.used || 0)],
            ['Disk Boş', formatBytes(metrics.disk?.free || 0)],
            ['Disk Kullanımı', (metrics.disk?.percent ?? 0) + '%'],
            ['Sunucu Uptime', metrics.uptime],
        ]);

        renderServerInfoTable('serverInfoPhpTable', [
            ['PHP Sürümü', metrics.php_version],
            ['SAPI', metrics.php_sapi],
            ['Zend Engine', metrics.php_env?.zend_version],
            ['Memory Limit', metrics.php_env?.memory_limit],
            ['Max Execution Time', metrics.php_env?.max_execution_time],
            ['Upload Max Filesize', metrics.php_env?.upload_max_filesize],
            ['Post Max Size', metrics.php_env?.post_max_size],
            ['Max Input Time', metrics.php_env?.max_input_time],
            ['Max Input Vars', metrics.php_env?.max_input_vars],
            ['Display Errors', metrics.php_env?.display_errors],
            ['Timezone', metrics.php_env?.timezone],
            ['Loaded php.ini', metrics.php_env?.loaded_ini],
            ['Yüklü Extension', metrics.php_env?.extensions_count],
        ]);

        renderServerInfoTable('serverInfoMysqlTable', [
            ['Sunucu Sürümü', metrics.mysql?.server_version || metrics.mysql_version],
            ['Client Sürümü', metrics.mysql?.client_version],
            ['Bağlantı', metrics.mysql?.connection_status],
            ['Character Set', metrics.mysql?.character_set_server],
            ['Collation', metrics.mysql?.collation_server],
            ['Max Connections', metrics.mysql?.max_connections],
            ['Max Allowed Packet', metrics.mysql?.max_allowed_packet],
            ['InnoDB Buffer Pool', metrics.mysql?.innodb_buffer_pool_size],
            ['SQL Mode', metrics.mysql?.sql_mode],
            ['Time Zone', metrics.mysql?.time_zone],
            ['Host', metrics.database?.host],
            ['Kullanıcı', metrics.database?.user],
        ]);

        renderServerInfoTable('serverInfoDbTable', [
            ['Veritabanı', metrics.database?.name],
            ['Host', metrics.database?.host],
            ['Kullanıcı', metrics.database?.user],
            ['Tablo Sayısı', Number(metrics.database?.table_count || 0).toLocaleString('tr-TR')],
            ['Toplam Boyut', metrics.database?.formatted_size],
            ['Toplam Satır', Number(metrics.database?.total_rows || 0).toLocaleString('tr-TR')],
        ]);

        renderServerInfoTable('serverInfoBackupTable', [
            ['Yedek Klasörü', metrics.server?.disk_path],
            ['Yedek Sayısı', Number(metrics.backup_dir?.count || 0).toLocaleString('tr-TR')],
            ['Toplam Yedek Boyutu', metrics.backup_dir?.formatted_size],
            ['Son Başarılı Yedek', metrics.backup_dir?.last_successful?.name || 'Yok'],
            ['Son Yedek Boyutu', metrics.backup_dir?.last_successful?.formatted_size || 'N/A'],
            ['Son Yedek Zamanı', metrics.backup_dir?.last_successful?.mtime || 'N/A'],
        ]);

        const extEl = document.getElementById('serverInfoExtensions');
        if (extEl) {
            extEl.innerHTML = (metrics.php_extensions || []).map(ext =>
                `<span class="server-extension-badge">${escapeHtml(ext)}</span>`
            ).join('');
        }
    }

    function openServerInfo() {
        const overlay = document.getElementById('serverInfoOverlay');
        if (!overlay) return;
        overlay.classList.add('open');
        overlay.setAttribute('aria-hidden', 'false');
        if (latestServerMetrics) renderServerInfo(latestServerMetrics);
        loadDashboard();
    }

    function closeServerInfo() {
        const overlay = document.getElementById('serverInfoOverlay');
        if (!overlay) return;
        overlay.classList.remove('open');
        overlay.setAttribute('aria-hidden', 'true');
    }

    let liveMetricsTimer = null;
    let liveMetricsBusy = false;

    function formatLiveBytes(bytes) {
        const n = Number(bytes) || 0;
        if (n < 1024) return n + ' B';
        const units = ['KB', 'MB', 'GB', 'TB'];
        let value = n / 1024;
        let i = 0;
        while (value >= 1024 && i < units.length - 1) {
            value /= 1024;
            i++;
        }
        return value.toFixed(value >= 100 ? 0 : 1) + ' ' + units[i];
    }

    async function refreshLiveMetrics() {
        if (liveMetricsBusy || document.hidden) return;
        liveMetricsBusy = true;
        try {
            // apiRequest zaten mevcut CSRF mekanizmasını kullanıyor.
            const res = await apiRequest('live_metrics', { _: Date.now() });
            const m = res.data || {};
            const cpu = m.cpu || {};
            const ram = m.ram || {};
            const disk = m.disk || {};

            const cpuPct = Math.round(Number(cpu.percent) || 0);
            const ramPct = Math.round(Number(ram.percent) || 0);
            const diskPct = Math.round(Number(disk.percent) || 0);

            const cpuPctEl = document.getElementById('m-cpu-pct');
            const cpuLoadEl = document.getElementById('m-cpu-load');
            const cpuCoresEl = document.getElementById('m-cpu-cores');
            const cpuBar = document.getElementById('m-cpu-bar');

            const ramPctEl = document.getElementById('m-ram-pct');
            const ramUsedEl = document.getElementById('m-ram-used');
            const ramTotalEl = document.getElementById('m-ram-total');
            const ramBar = document.getElementById('m-ram-bar');

            const diskPctEl = document.getElementById('m-disk-pct');
            const diskFreeEl = document.getElementById('m-disk-free');
            const diskTotalEl = document.getElementById('m-disk-total');
            const diskBar = document.getElementById('m-disk-bar');

            if (cpuPctEl) cpuPctEl.textContent = cpuPct + '%';
            if (cpuLoadEl) cpuLoadEl.textContent = Number(cpu.load_1min || 0).toFixed(2);
            if (cpuCoresEl) cpuCoresEl.textContent = cpu.cores || 1;
            if (cpuBar) cpuBar.style.width = cpuPct + '%';

            if (ramPctEl) ramPctEl.textContent = ramPct + '%';
            if (ramUsedEl) ramUsedEl.textContent = formatLiveBytes(ram.used);
            if (ramTotalEl) ramTotalEl.textContent = formatLiveBytes(ram.total);
            if (ramBar) ramBar.style.width = ramPct + '%';

            if (diskPctEl) diskPctEl.textContent = diskPct + '%';
            if (diskFreeEl) diskFreeEl.textContent = formatLiveBytes(disk.free);
            if (diskTotalEl) diskTotalEl.textContent = formatLiveBytes(disk.total);
            if (diskBar) diskBar.style.width = diskPct + '%';

            // Sunucu Bilgisi açıksa dairesel göstergeleri aynı canlı veriden güncelle.
            setServerGauge('serverGaugeCpu', cpuPct, 'serverGaugeCpuValue', 'serverGaugeCpuMeta',
                'Load ' + Number(cpu.load_1min || 0).toFixed(2) + ' · ' + (cpu.cores || 1) + ' çekirdek');
            setServerGauge('serverGaugeRam', ramPct, 'serverGaugeRamValue', 'serverGaugeRamMeta',
                formatLiveBytes(ram.used) + ' / ' + formatLiveBytes(ram.total));
            setServerGauge('serverGaugeDisk', diskPct, 'serverGaugeDiskValue', 'serverGaugeDiskMeta',
                formatLiveBytes(disk.used) + ' / ' + formatLiveBytes(disk.total));

            // Sunucu Bilgisi açıksa mevcut render mekanizmasını da güncelle.
            if (typeof latestServerMetrics === 'object' && latestServerMetrics) {
                latestServerMetrics.cpu = Object.assign({}, latestServerMetrics.cpu, cpu);
                latestServerMetrics.ram = Object.assign({}, latestServerMetrics.ram, ram);
                latestServerMetrics.disk = Object.assign({}, latestServerMetrics.disk, disk);
                const serverInfoOverlay = document.getElementById('serverInfoOverlay');
                if (serverInfoOverlay && serverInfoOverlay.classList.contains('open')) {
                    refreshOpenServerInfoResources();
                }
            }
        } catch (e) {
            // Canlı metrik hatası ana dashboard/log/SQL işlemlerini etkilemez.
        } finally {
            liveMetricsBusy = false;
            if (!document.hidden) {
                clearTimeout(liveMetricsTimer);
                liveMetricsTimer = setTimeout(refreshLiveMetrics, 2000);
            }
        }
    }

    function startLiveMetrics() {
        clearTimeout(liveMetricsTimer);
        liveMetricsTimer = null;
        refreshLiveMetrics();
    }

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) startLiveMetrics();
        else clearTimeout(liveMetricsTimer);
    });

document.addEventListener('DOMContentLoaded', () => {
        document.addEventListener('change', (event) => {
            if (event.target?.id === 'selectAllBackups') {
                document.querySelectorAll('#backups-list .backup-select').forEach(cb => {
                    cb.checked = event.target.checked;
                });
                updateBackupSelectionUI();
                persistBackupSelection();
            } else if (event.target?.classList?.contains('backup-select')) {
                updateBackupSelectionUI();
                persistBackupSelection();
            }
        });

        document.addEventListener('click', (event) => {
            const bulkBtn = event.target?.closest?.('#bulkDeleteBackupsBtn');
            if (bulkBtn) {
                event.preventDefault();
                event.stopPropagation();
                if (!bulkBtn.disabled) bulkDeleteBackups();
                return;
            }
        });

        // Veritabanı boşaltma butonu dinamik DOM değişikliklerinden sonra da çalışsın.
        document.addEventListener('click', (event) => {
            const target = event.target?.closest?.('#dbEmptyDatabaseBtn');
            if (!target) return;
            event.preventDefault();
            if (!target.disabled) emptyEntireDatabase();
        });

        const backupsList = document.getElementById('backups-list');

        const runBtn = document.getElementById('btnRunBackup');
        const openServerInfoBtn = document.getElementById('btnOpenServerInfo');
        const closeServerInfoBtn = document.getElementById('btnCloseServerInfo');
        const refreshServerInfoBtn = document.getElementById('btnRefreshServerInfo');
        const serverInfoOverlay = document.getElementById('serverInfoOverlay');

        if (openServerInfoBtn) openServerInfoBtn.addEventListener('click', openServerInfo);
        if (closeServerInfoBtn) closeServerInfoBtn.addEventListener('click', closeServerInfo);
        if (refreshServerInfoBtn) refreshServerInfoBtn.addEventListener('click', loadDashboard);
        if (serverInfoOverlay) {
            serverInfoOverlay.addEventListener('click', (event) => {
                if (event.target === serverInfoOverlay) closeServerInfo();
            });
        }

        const clearLogsBtn = document.getElementById('btnClearLogs');
        const openLogsBtn = document.getElementById('btnOpenLogs');
        const closeLogsBtn = document.getElementById('btnCloseLogs');
        const logModalOverlay = document.getElementById('logModalOverlay');
        const logoutBtn = document.getElementById('btnLogout');
        const logSearch = document.getElementById('logSearch');
        const logLevelFilter = document.getElementById('logLevelFilter');
        const backupsBody = document.getElementById('backups-list');

        if (runBtn) runBtn.addEventListener('click', startFullBackup);
        if (clearLogsBtn) clearLogsBtn.addEventListener('click', clearLogs);
        if (openLogsBtn) openLogsBtn.addEventListener('click', () => {
            if (logModalOverlay) {
                logModalOverlay.classList.add('open');
                logModalOverlay.setAttribute('aria-hidden', 'false');
                filterLogs();
            }
        });
        if (closeLogsBtn) closeLogsBtn.addEventListener('click', () => {
            if (logModalOverlay) {
                logModalOverlay.classList.remove('open');
                logModalOverlay.setAttribute('aria-hidden', 'true');
            }
        });
        if (logModalOverlay) logModalOverlay.addEventListener('click', (event) => {
            if (event.target === logModalOverlay) {
                logModalOverlay.classList.remove('open');
                logModalOverlay.setAttribute('aria-hidden', 'true');
            }
        });
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && document.getElementById('serverInfoOverlay')?.classList.contains('open')) {
                closeServerInfo();
            }
            if (event.key === 'Escape' && document.getElementById('vedoConfirmOverlay')?.classList.contains('open')) {
                closeConfirm(false);
            }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && logModalOverlay?.classList.contains('open')) {
                logModalOverlay.classList.remove('open');
                logModalOverlay.setAttribute('aria-hidden', 'true');
            }
        });
        if (logSearch) logSearch.addEventListener('input', filterLogs);
        if (logLevelFilter) logLevelFilter.addEventListener('change', filterLogs);
        // Logout artık CSRF korumalı POST formu ile çalışır.
        const copyCronBtn = document.getElementById('btnCopyCron');
        if (copyCronBtn) copyCronBtn.addEventListener('click', copyCronCommand);

        // PHPMyAdmin benzeri veritabanı gezginini büyük modal içinde açıp kapatır.
        const dbExplorerOverlay = document.getElementById('dbExplorerOverlay');
        const openDbExplorerBtn = document.getElementById('btnOpenDbExplorer');
        const closeDbExplorerBtn = document.getElementById('btnCloseDbExplorer');
        function openDbExplorer() {
            if (!dbExplorerOverlay) return;
            dbExplorerOverlay.classList.add('open');
            dbExplorerOverlay.setAttribute('aria-hidden', 'false');
            document.body.classList.add('db-modal-open');
            if (typeof loadDatabaseTables === 'function') loadDatabaseTables(false);
        }
        function closeDbExplorer() {
            if (!dbExplorerOverlay) return;
            dbExplorerOverlay.classList.remove('open');
            dbExplorerOverlay.setAttribute('aria-hidden', 'true');
            document.body.classList.remove('db-modal-open');
        }
        if (openDbExplorerBtn) openDbExplorerBtn.addEventListener('click', openDbExplorer);
        if (closeDbExplorerBtn) closeDbExplorerBtn.addEventListener('click', closeDbExplorer);
        if (dbExplorerOverlay) {
            dbExplorerOverlay.addEventListener('click', (event) => {
                if (event.target === dbExplorerOverlay) closeDbExplorer();
            });
        }
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && dbExplorerOverlay?.classList.contains('open')) closeDbExplorer();
        });
        const dbList = document.getElementById('dbTableList');
        if (dbList) dbList.addEventListener('click', (e) => { const item = e.target.closest('[data-db-table]'); if (item) selectDatabaseTable(item.dataset.dbTable); });
        document.getElementById('dbStructureBtn')?.addEventListener('click', loadDatabaseStructure);
        document.getElementById('dbAnalyzeBtn')?.addEventListener('click', () => dbMaintenance('analyze'));
        document.getElementById('dbRepairBtn')?.addEventListener('click', () => dbMaintenance('repair'));
        document.getElementById('dbOptimizeBtn')?.addEventListener('click', () => dbMaintenance('optimize'));
        document.getElementById('dbTruncateBtn')?.addEventListener('click', () => dbDestructive('truncate'));
        document.getElementById('dbDropBtn')?.addEventListener('click', () => dbDestructive('drop'));
        document.getElementById('dbRefreshBtn')?.addEventListener('click', () => loadDatabaseTables(false));
        document.getElementById('dbPrevBtn')?.addEventListener('click', () => { if (dbOffset >= DB_PAGE_SIZE) { dbOffset -= DB_PAGE_SIZE; loadDatabaseTableData(); } });
        document.getElementById('dbNextBtn')?.addEventListener('click', () => { dbOffset += DB_PAGE_SIZE; loadDatabaseTableData(); });

        // Dinamik backup satırları için tek event listener (CSP uyumlu).
        if (backupsBody) {
            backupsBody.addEventListener('click', (e) => {
                const btn = e.target.closest('[data-action][data-file]');
                if (!btn) return;
                const file = btn.dataset.file || '';
                const action = btn.dataset.action;
                if (!file) return;

                if (action === 'download') downloadFile(file);
                else if (action === 'verify') verifyFile(file);
                else if (action === 'restore') triggerRestore(file);
                else if (action === 'delete') deleteFile(file);
            });
        }

        loadDashboard();
        startLiveMetrics();
        loadDatabaseTables(true);

        (async () => {
            try {
                const res = await apiRequest('get_active_cli_jobs', {});
                const jobs = res?.data?.jobs || [];
                if (jobs.length > 0 && !activeCliJobId) {
                    activeCliJobId = jobs[0].job_id || '';
                    document.getElementById('live-progress-panel').style.display = 'block';
                    startProgressPolling();
                }
            } catch (e) {
            }
        })();
});
</script>

</body>
</html>
