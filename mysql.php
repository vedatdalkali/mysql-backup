<?php
/**
 * ==============================================================================
 * VEDO MYSQL BACKUP (TEK DOSYA VERİTABANI YÖNETİM PANELİ) - ULTRA OPTİMİZE
 * ==============================================================================
 * PHP 8.0+ | MySQL 5.7+ / 8.0+ / MariaDB
 * Gelişmiş Yedekleme, Parçalı Geri Yükleme, Canlı Metrik İzleme ve Güvenlik
 * ==============================================================================
 */

declare(strict_types=1);

if (version_compare(PHP_VERSION, '8.0.0', '<')) {
    if (php_sapi_name() === 'cli') {
        fwrite(STDERR, "Minimum PHP 8.0.0 gereklidir. Mevcut: " . PHP_VERSION . "\n");
        exit(1);
    }
    http_response_code(500);
    echo "Bu sistem minimum PHP 8.0.0 sürümünü gerektirmektedir. Mevcut sürüm: " . PHP_VERSION;
    exit;
}

$required_extensions = [
    'pdo',
    'pdo_mysql',
    'json',
    'zlib',
    'session',
    'hash'
];

foreach ($required_extensions as $ext) {
    if (!extension_loaded($ext)) {
        die("PHP uzantısı eksik: {$ext}");
    }
}

// Global Sabit Tanımlamaları
define('VEDO_LINE_MAX_BUFFER', 4096);
define('VEDO_READ_CHUNK_BYTES', 524288); // 512 KB
define('VEDO_RESTORE_CHUNK_BYTES', 1048576); // 1 MB
define('VEDO_QUERY_BUFFER_MAX', 52428800); // 50 MB
define('VEDO_CHUNK_ROW_LARGE', 5000);
define('VEDO_CHUNK_ROW_MEDIUM', 2500);
define('VEDO_CHUNK_ROW_SMALL', 1500);
define('VEDO_CHUNK_ROW_DEFAULT', 800);
define('VEDO_MAX_LOG_SIZE', 5242880); // 5 MB

/**
 * Çıktı arabelleklemesini güvenli şekilde temizler ve başlatır.
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

/**
 * Güvenli dosya yazma kontrolü (3 denemeli retry mekanizması).
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
        usleep(50000); // 50ms bekle (Disk I/O toparlanması için)
    }

    if (!$written) {
        $lastError = error_get_last();
        $errMsg = $lastError['message'] ?? 'Bilinmeyen Disk I/O Hatası';
        if (class_exists('Logger')) {
            Logger::error("Dosya yazma başarısız [{$filepath}] ({$attempts} deneme yapıldı): {$errMsg}");
        }
        return false;
    }
    return true;
}

// ==========================================
// 1. MERKEZİ LOGLAMA SINIFI (GÜVENLİ ROTASYON VE LOCK)
// ==========================================
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

        if (self::$available && is_file(self::$logFile) && filesize(self::$logFile) > VEDO_MAX_LOG_SIZE) {
        $rotLockFile = self::$logDir . '/rotation.lock';
        $rotFp = @fopen($rotLockFile, 'c+');

        $locked = ($rotFp && flock($rotFp, LOCK_EX));

        if ($locked) {

            if (is_file(self::$logFile) && filesize(self::$logFile) > VEDO_MAX_LOG_SIZE) {

               for ($i = self::$maxRotateFiles - 1; $i >= 1; $i--) {

                    $old = self::$logDir . "/system.log.$i";
                    $new = self::$logDir . "/system.log." . ($i + 1);

                    if (is_file($old)) {
                        @rename($old, $new);
                    }
                }

                @rename(self::$logFile, self::$logDir . "/system.log.1");
            }

    fflush($rotFp);
    flock($rotFp, LOCK_UN);
}

if (is_resource($rotFp)) {
    fclose($rotFp);
}
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
    public static function debug(string $msg): void { self::log('DEBUG', $msg); }
}

// ==========================================
// 2. GÜVENLİK İÇİN NONCE & HTTP BAŞLIKLARI
// ==========================================
$nonce = base64_encode(random_bytes(16));

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: no-referrer");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';");

if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
}

header("Permissions-Policy: camera=(), microphone=(), geolocation=(), autoplay=(), fullscreen=(), payment=(), usb=(), serial=(), accelerometer=()");
header("Cross-Origin-Opener-Policy: same-origin");
header("Cross-Origin-Resource-Policy: same-origin");

// ==========================================
// 3. YAPILANDIRMA VE KURULUM
// ==========================================
$config = [
    'db_host'            => 'localhost',
    'db_user'            => 'database kullanıcı adını yazın',
    'db_pass'            => 'şifrenizi yazın',
    'db_name'            => 'database adını yazın',
    'auth_user'          => 'giriş için kullanıcı adı yazın',
    'auth_pass'          => 'giriş için şifrenizi yazın',
    'max_backups'        => 2880,
    'cron_token'         => 'sql_backup_' . substr(md5('sql_backup_salt'), 0, 10),
    'memory_limit'       => '512M',
    'backup_chunk'       => 1000,
    'max_insert_rows'    => 500,
    'restore_chunk'      => VEDO_RESTORE_CHUNK_BYTES,
    'read_chunk'         => VEDO_READ_CHUNK_BYTES,
    'use_transaction'    => true,
    'use_persistent_pdo' => false,
    'max_login_attempts' => 5,
    'lockout_time'       => 900,
    'lock_timeout'       => 60,
    'log_rotate_count'   => 5
];

$backup_dir = __DIR__ . '/mysqlyedek';

if (!is_dir($backup_dir)) {
    if (!mkdir($backup_dir, 0755, true) && !is_dir($backup_dir)) {
        if (php_sapi_name() === 'cli') exit(1);
        http_response_code(500);
        die("Kritik Hata: Yedekleme klasörü (" . htmlspecialchars($backup_dir) . ") oluşturulamadı!");
    }
}

Logger::init($backup_dir, (int)$config['log_rotate_count']);

$htaccess_path = $backup_dir . '/.htaccess';
if (!file_exists($htaccess_path)) {
    safe_file_put_contents($htaccess_path, "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>");
}

$index_path = $backup_dir . '/index.html';
if (!file_exists($index_path)) {
    safe_file_put_contents($index_path, '');
}

if (!is_writable(__DIR__)) {
    die("Bulunulan dizin yazılabilir değil.");
}

if (!is_writable($backup_dir)) {
    die("Yedek klasörü yazılabilir değil.");
}

// ==========================================
// 4. ŞEMA CACHE SINIFI (LRU CACHE)
// ==========================================
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

// ==========================================
// 5. YARDIMCI VE PERFORMANS FONKSİYONLARI
// ==========================================

function validate_path_safe(string $filePath, string $baseDir): string {
    $realPath = realpath($filePath);
    $realBase = realpath($baseDir);
    if (!$realPath || !$realBase || !str_starts_with($realPath, $realBase)) {
        throw new Exception("Güvenlik İhlali: Yetkisiz dizin erişimi engellendi!");
    }
    return $realPath;
}

function json_response(bool $success, string $message = '', array $data = [], int $httpCode = 200): void {
    clear_buffers();
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data'    => $data
    ], JSON_UNESCAPED_UNICODE);
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
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $table)) return VEDO_CHUNK_ROW_DEFAULT;
    
    $base_chunk = VEDO_CHUNK_ROW_DEFAULT;
    try {
        $stmt = $pdo->prepare("SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?");
        $stmt->execute([$db_name, $table]);
        $rows = (int)($stmt->fetchColumn() ?? 0);
        
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

function acquire_system_lock(string $backup_dir, string $type = 'general', int $timeout = 60) {
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
                        @exec(
                            "powershell -NoProfile -Command \"Get-Process -Id {$pid} -ErrorAction SilentlyContinue\"",
                            $win_check
                        );

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

function update_system_lock_heartbeat($lock_fp): void {
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

function release_system_lock($lock_fp): void {
    if (is_resource($lock_fp)) {
        flock($lock_fp, LOCK_UN);
        fclose($lock_fp);
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

    $now = time();
    $sql_files = [];

    try {
        $iterator = new DirectoryIterator($real_backup_dir);
        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isDot() || !$fileinfo->isFile()) continue;

            $filename = $fileinfo->getFilename();

            if (str_ends_with($filename, '.progress.json')) {
                if (($now - $fileinfo->getMTime()) > 86400) {
                    @unlink($fileinfo->getPathname());
                }
                continue;
            }

            if (str_ends_with($filename, '.sql.gz')) {
                $sql_files[] = [
                    'path' => $fileinfo->getPathname(),
                    'mtime' => $fileinfo->getMTime(),
                    'name' => $filename
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

                $filename = $sql_files[$i]['name'];
                $cp_file = $dir . '/' . md5($filename) . '.progress.json';
                if (is_file($cp_file)) {
                    @unlink(validate_path_safe($cp_file, $real_backup_dir));
                }
            } catch (Exception $e) {
                Logger::warning("Eski yedek silinirken hata oluştu: " . $e->getMessage());
            }
        }
    }
}

function escape_string_safe($v, ?PDO $pdo = null): string {
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
                $instances[$key]->query("SELECT 1;");
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
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => false,
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
        return (int)($res['ts'] ?? 0);
    } catch (Exception $e) {
        return 0;
    }
}

function check_sufficient_disk_space(PDO $pdo, string $db_name, string $dir): void
{
    $free_space = @disk_free_space($dir);

    // Bazı shared hostinglerde disk_free_space() çalışmaz.
    if ($free_space === false) {
        Logger::warning("disk_free_space() okunamadı. Disk kontrolü atlandı.");
        return;
    }

    $db_size = get_database_size_bytes($pdo, $db_name);

    // Veritabanının yaklaşık %50'si kadar boş alan yeterli kabul edilir.
    $estimated_needed = max(
        50 * 1024 * 1024,
        (int)($db_size * 0.50)
    );

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
        $ps_out = [];
        $exit_code = 1;
        $available_bytes = 0;

if (function_exists('exec')) {

    $ps_out = [];
    $exit_code = 1;

            @exec(
                'powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory"',
                $ps_out,
             $exit_code
          );

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
        $config['memory_limit'] = calculate_dynamic_memory_limit($pdo, $config['db_name']);
        $initialized = true;
    }
    return $pdo;
}

function get_single_table_engine(?PDO $pdo, string $db_name, string $table): string {
    $cache_key = "engine.{$db_name}.{$table}";
    $cached = SchemaCache::get($cache_key);
    if ($cached !== null) return $cached;
    if ($pdo === null) return '';

    try {
        $stmt = $pdo->prepare("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?");
        $stmt->execute([$db_name, $table]);
        $engine = strtoupper((string)($stmt->fetchColumn() ?? ''));
        SchemaCache::set($cache_key, $engine);
        return $engine;
    } catch (Exception $e) {
        Logger::error("Engine bilgileri çekilirken hata oluştu: " . $e->getMessage());
    }
    return '';
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
        
        if (!empty($cols)) {
            SchemaCache::set($cache_key, $cols);
            return $cols;
        }

        $stmt = $pdo->prepare("
            SELECT s.COLUMN_NAME
            FROM information_schema.STATISTICS s
            JOIN information_schema.COLUMNS c 
              ON s.TABLE_SCHEMA = c.TABLE_SCHEMA 
             AND s.TABLE_NAME = c.TABLE_NAME 
             AND s.COLUMN_NAME = c.COLUMN_NAME
            WHERE s.TABLE_SCHEMA = ? AND s.TABLE_NAME = ? AND s.NON_UNIQUE = 0 AND c.IS_NULLABLE = 'NO'
            ORDER BY s.INDEX_NAME ASC, s.SEQ_IN_INDEX ASC
        ");
        $stmt->execute([$db_name, $table]);
        $unique_cols = $stmt->fetchAll(PDO::FETCH_COLUMN);

        if (!empty($unique_cols)) {
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
        if ($col) {
            return (string)$col;
        }
    } catch (Exception $e) {
        Logger::error("get_table_auto_increment_key hatası ($table): " . $e->getMessage());
    }
    return '';
}

function single_table_maintenance(PDO $pdo, string $t, string $engine = ''): void {
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $t)) return;
    $garbage = ['log', 'logs', 'session', 'sessions', 'cache', 'caches', 'webhook_history', 'tmp', 'temp'];
    $lower_t = strtolower($t);
    
    foreach ($garbage as $g) {
        if ($lower_t === $g || str_ends_with($lower_t, '_'.$g)) {
            try {
                $stmt = $pdo->prepare("TRUNCATE TABLE `$t`");
                $stmt->execute();
                $stmt->closeCursor();
            } catch (Exception $e) {
                Logger::error("TRUNCATE hatası ($t): " . $e->getMessage());
            }
            return;
        }
    }

    try {
        if (in_array($engine, ['MYISAM', 'ARIA'], true)) {
            $checkStmt = $pdo->prepare("CHECK TABLE `$t` QUICK");
            $checkStmt->execute();
            $needsRepair = false;

            if ($checkStmt) {
                while ($row = $checkStmt->fetch(PDO::FETCH_ASSOC)) {
                    $msgType = strtolower($row['Msg_type'] ?? '');
                    $msgText = strtolower($row['Msg_text'] ?? '');
                    if ($msgType === 'error' || ($msgType === 'status' && $msgText !== 'ok')) {
                        $needsRepair = true;
                        break;
                    }
                }
                $checkStmt->closeCursor();
            }

            if ($needsRepair) {
                $repairStmt = $pdo->prepare("REPAIR TABLE `$t`");
                $repairStmt->execute();
                $repairStmt->closeCursor();
            }
        }
    } catch (Exception $e) {
        Logger::error("single_table_maintenance hatası ($t): " . $e->getMessage());
    }
}

function format_bytes($bytes, int $precision = 2): string {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max((float)$bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min((int)$pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function safe_gzwrite($stream, string $data, bool $flush = false): void {
    $length = strlen($data);
    if ($length === 0) return;
    $written = gzwrite($stream, $data);
    if ($written === false || $written < $length) {
        $err = gzerror($stream, $errnum);
        throw new Exception("Gzip arşivine yazma başarısız oldu! [GzError: {$err}]");
    }
    if ($flush) {
        gzflush($stream, ZLIB_SYNC_FLUSH);
    }
}

function export_single_table_to_stream(PDO $pdo, string $table, $stream, string $db_name, int $chunk_size_setting = 1000, int $max_insert_rows = 500): void {
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $table)) {
        throw new Exception("Geçersiz tablo tanımı tespit edildi.");
    }

    $engine = get_single_table_engine($pdo, $db_name, $table);
    single_table_maintenance($pdo, $table, $engine);

    $stmtInfo = $pdo->prepare("SHOW CREATE TABLE `{$table}`");
    $stmtInfo->execute();
    $createTableStmt = $stmtInfo->fetch();
    $stmtInfo->closeCursor();
    
    $createTableSql = $createTableStmt['Create Table'] ?? $createTableStmt['Create View'] ?? '';

    if (!empty($createTableSql)) {
        $pattern = '/DEFINER\s*=\s*(`[^`]+`@`[^`]+`|CURRENT_USER)|\s+(ROW_FORMAT|ALGORITHM|DEFAULT\s+ENCRYPTION|SECONDARY_ENGINE|ENGINE_ATTRIBUTE)\s*=\s*[\'"]?[^\s;]+[\'"]?|\s+TABLESPACE\s+`?[a-zA-Z0-9_]+`?(\s+STORAGE\s+[a-zA-Z0-9_]+)?|\s+AUTO_INCREMENT=\d+/i';
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

    $max_buffer_bytes = 2 * 1024 * 1024; // 2MB Güvenli Sabit Tampon

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

function verify_and_checksum_gzip(string $file_path): string {
    if (!is_file($file_path)) throw new Exception("Yedek dosyası bulunamadı.");

    $ctx = hash_init('sha256');
    $fp = fopen($file_path, 'rb');
    if (!$fp) throw new Exception("Yedek dosyası okuma modunda açılamadı!");

    $gz = gzopen($file_path, 'rb');
    if (!$gz) {
        fclose($fp);
        throw new Exception("Gzip arşivi açılamadı, dosya bozulmuş olabilir!");
    }

    while (!feof($fp)) {
        $chunk = fread($fp, 262144);
        if ($chunk !== false && $chunk !== '') {
            hash_update($ctx, $chunk);
        }
        if (!gzeof($gz)) {
            if (gzread($gz, 524288) === false) {
                gzclose($gz);
                fclose($fp);
                throw new Exception("Gzip bütünlük testi başarısız!");
            }
        }
    }
    fclose($fp);
    gzclose($gz);

    $hash = hash_final($ctx);
    $sha_path = $file_path . '.sha256';
    
    if (!safe_file_put_contents($sha_path, $hash . "  " . basename($file_path) . "\n", LOCK_EX)) {
        throw new Exception("SHA256 imza dosyası yazılamadı!");
    }

    return $hash;
}

function verify_backup_checksum(string $file_path): string {
    if (!is_file($file_path)) throw new Exception("Yedek dosyası bulunamadı.");

    $sha_file = $file_path . '.sha256';
    if (!is_file($sha_file)) throw new Exception("Checksum (.sha256) dosyası bulunamadı!");

    $sha_content = trim((string)file_get_contents($sha_file));
    $parts = preg_split('/\s+/', $sha_content);
    $expected_hash = $parts[0] ?? '';

    if (empty($expected_hash)) throw new Exception("Geçersiz checksum dosyası biçimi.");

    $ctx = hash_init('sha256');
    $fp = fopen($file_path, 'rb');
    if (!$fp) throw new Exception("Yedek okunamadı!");

    $gz = gzopen($file_path, 'rb');
    if (!$gz) {
        fclose($fp);
        throw new Exception("Gzip arşivi açılamadı!");
    }

    while (!feof($fp)) {
        $chunk = fread($fp, 262144);
        if ($chunk !== false && $chunk !== '') {
            hash_update($ctx, $chunk);
        }
        if (!gzeof($gz)) {
            if (gzread($gz, 524288) === false) {
                gzclose($gz);
                fclose($fp);
                throw new Exception("Gzip bütünlük testi BAŞARISIZ!");
            }
        }
    }
    fclose($fp);
    gzclose($gz);

    $current_hash = hash_final($ctx);

    if (!hash_equals($expected_hash, $current_hash)) {
        throw new Exception("Checksum uyuşmazlığı! Dosya içeriği bozulmuş veya değiştirilmiş.");
    }

    return $current_hash;
}

function verify_database_integrity_after_restore(PDO $pdo, string $db_name, bool $quick = true): array {
    $report = [
        'status' => 'OK',
        'tables_checked' => 0,
        'fk_issues' => 0,
        'errors' => []
    ];
    try {
        $stmtTables = $pdo->query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'");
        $tables = $stmtTables->fetchAll(PDO::FETCH_COLUMN);
        $stmtTables->closeCursor();

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
            
            try {
                $pdo->exec("ANALYZE TABLE `{$t}`");
            } catch (Exception $e) {}
        }

        try {
            $fkStmt = $pdo->prepare("
                SELECT TABLE_NAME, COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME 
                FROM information_schema.KEY_COLUMN_USAGE 
                WHERE TABLE_SCHEMA = ? AND REFERENCED_TABLE_NAME IS NOT NULL
            ");
            $fkStmt->execute([$db_name]);
            $fks = $fkStmt->fetchAll();
            foreach ($fks as $fk) {
                $checkFk = $pdo->query("SELECT COUNT(*) FROM `{$fk['TABLE_NAME']}` t LEFT JOIN `{$fk['REFERENCED_TABLE_NAME']}` r ON t.`{$fk['COLUMN_NAME']}` = r.`{$fk['REFERENCED_COLUMN_NAME']}` WHERE t.`{$fk['COLUMN_NAME']}` IS NOT NULL AND r.`{$fk['REFERENCED_COLUMN_NAME']}` IS NULL LIMIT 1");
                if ($checkFk && (int)$checkFk->fetchColumn() > 0) {
                    $report['fk_issues']++;
                    $report['errors'][] = "FK İhlali: {$fk['TABLE_NAME']}.{$fk['COLUMN_NAME']} -> {$fk['REFERENCED_TABLE_NAME']}.{$fk['REFERENCED_COLUMN_NAME']}";
                    $report['status'] = 'WARNING';
                }
            }
        } catch (Exception $eFK) {}

    } catch (Exception $e) {
        $report['status'] = 'ERROR';
        $report['errors'][] = $e->getMessage();
    }
    return $report;
}

// ==========================================
// RESTORE FONKSİYONLARI
// ==========================================

function restore_read_chunk($gz, int $chunk_read_size, int &$bytes_processed) {
    $buffer = gzread($gz, $chunk_read_size);
    if ($buffer === false || $buffer === '') return false;
    $bytes_processed += strlen($buffer);
    return $buffer;
}

function restore_parse_buffer(string $buffer, string &$queryBuffer, bool &$inString, string &$stringChar, bool &$inCommentMulti, bool &$inCommentSingle, bool &$escaped, string &$currentDelimiter): array {
    $extractedQueries = [];
    $bufLen = strlen($buffer);

    for ($i = 0; $i < $bufLen; $i++) {
        $char = $buffer[$i];
        $nextChar = ($i + 1 < $bufLen) ? $buffer[$i + 1] : '';

        if (strlen($queryBuffer) > VEDO_QUERY_BUFFER_MAX) {
            throw new Exception("Sorgu arabelleği çok büyüdü (50MB+). SQL dosyasını kontrol edin.");
        }

        if ($inCommentMulti) {
            $closePos = strpos($buffer, '*/', $i);
            if ($closePos !== false) {
                $queryBuffer .= substr($buffer, $i, $closePos - $i + 2);
                $i = $closePos + 1;
                $inCommentMulti = false;
            } else {
                $queryBuffer .= substr($buffer, $i);
                break;
            }
            continue;
        }

        if ($inCommentSingle) {
            $queryBuffer .= $char;
            if ($char === "\n") $inCommentSingle = false;
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
            }
            continue;
        }

        if ($char === '/' && $nextChar === '*') {
            $inCommentMulti = true;
            $queryBuffer .= '/*';
            $i++;
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
            $inCommentSingle = true;
            $queryBuffer .= $char;
            continue;
        }

        if ($char === "'" || $char === '"' || $char === '`') {
            $inString = true;
            $stringChar = $char;
            $queryBuffer .= $char;
            continue;
        }

        $queryBuffer .= $char;

        $delimLen = strlen($currentDelimiter);
        if ($delimLen > 0 && $char === $currentDelimiter[$delimLen - 1] && substr($queryBuffer, -$delimLen) === $currentDelimiter) {
            $sqlToExec = trim(substr($queryBuffer, 0, -$delimLen));
            
            if (!empty($sqlToExec)) {
                if (preg_match('/^DELIMITER\s+([^\s\r\n\t]+)/iu', $sqlToExec, $matches)) {
                    $currentDelimiter = preg_replace('/^\s+|\s+$/u', '', $matches[1]);
                } else {
                    $extractedQueries[] = $sqlToExec;
                }
            }
            $queryBuffer = '';
        }
    }

    return $extractedQueries;
}

function restore_execute_sql(PDO &$pdo, array $queries, int &$processed_tables_count, int &$processed_rows_count, string $backup_dir, array $config = []): int {
    $executed = 0;
    $max_retries = 5;

    $allowed_sql_prefixes = [
        'CREATE TABLE', 'CREATE OR REPLACE TABLE', 'CREATE TEMPORARY TABLE', 'DROP TABLE', 'DROP TABLE IF EXISTS', 'DROP TEMPORARY TABLE',
        'CREATE VIEW', 'CREATE OR REPLACE VIEW', 'DROP VIEW', 'DROP VIEW IF EXISTS',
        'CREATE TRIGGER', 'DROP TRIGGER', 'DROP TRIGGER IF EXISTS',
        'CREATE FUNCTION', 'DROP FUNCTION', 'DROP FUNCTION IF EXISTS',
        'CREATE PROCEDURE', 'DROP PROCEDURE', 'DROP PROCEDURE IF EXISTS',
        'CREATE EVENT', 'DROP EVENT', 'DROP EVENT IF EXISTS',
        'CREATE SEQUENCE', 'DROP SEQUENCE', 'DROP SEQUENCE IF EXISTS',
        'CREATE INDEX', 'DROP INDEX', 'DROP INDEX IF EXISTS',
        'RENAME TABLE', 'CREATE DATABASE', 'USE',
        'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'TRUNCATE',
        'ALTER TABLE', 'ANALYZE TABLE', 'OPTIMIZE TABLE', 'CHECK TABLE',
        'LOCK TABLES', 'UNLOCK TABLES',
        'DELIMITER', 'START TRANSACTION', 'COMMIT', 'BEGIN'
    ];

    $allowed_set_variables = [
        'FOREIGN_KEY_CHECKS', 'UNIQUE_CHECKS', 'SQL_MODE', 
        'TIME_ZONE', 'NAMES', 'CHARACTER_SET_CLIENT', 
        'CHARACTER_SET_RESULTS', 'CHARACTER_SET_CONNECTION',
        'AUTOCOMMIT', 'SQL_LOG_BIN'
    ];

    foreach ($queries as $sql) {
        $sql_trimmed = ltrim($sql);
        $sql_upper = strtoupper($sql_trimmed);

        if (str_starts_with($sql_trimmed, '--') || str_starts_with($sql_trimmed, '#')) {
            continue;
        }

        if (str_starts_with($sql_trimmed, '/*') && preg_match('/^\/\*!\d+\s+(.+)\*\/$/s', $sql_trimmed, $m_comment)) {
            $sql_trimmed = trim($m_comment[1]);
            $sql_upper = strtoupper($sql_trimmed);
        }

        $is_allowed = false;

        foreach ($allowed_sql_prefixes as $prefix) {
            if (str_starts_with($sql_upper, $prefix)) {
                $is_allowed = true;
                break;
            }
        }

        if (!$is_allowed && str_starts_with($sql_upper, 'SET ')) {
            if (!str_contains($sql_upper, 'GLOBAL') && !str_contains($sql_upper, 'PERSIST')) {
                foreach ($allowed_set_variables as $set_var) {
                    if (preg_match('/^\s*SET\s+(SESSION\s+|@@SESSION\.|@@LOCAL\.|@@)?' . preg_quote($set_var, '/') . '\s*=/i', $sql_trimmed)) {
                        $is_allowed = true;
                        break;
                    }
                }
            }
        }

        if (!$is_allowed) {
            $error_message = "Güvenlik Engeli: İzin verilmeyen SQL komutu tespit edildi! (" . substr($sql_trimmed, 0, 500) . "...)";
            Logger::error($error_message);
            throw new Exception($error_message);
        }

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
            Logger::error("SQL Hatası (Deneme {$attempt}): {$last_error_message} | Sorgu: " . substr($sql_trimmed, 0, 500));
            throw new Exception("SQL Çalıştırma Hatası: " . $last_error_message);
        }

        $executed++;
        restore_calculate_progress($sql, $processed_tables_count, $processed_rows_count);
    }
    return $executed;
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
        $upper_prefix = strtoupper(substr($trimmed, 0, 20));
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

// ==========================================
// 6. OTOMATİK ZAMANLANMIŞ GÖREV (CRON JOB)
// ==========================================
$is_cli_cron = (
    php_sapi_name() === 'cli' &&
    isset($argv) &&
    in_array($config['cron_token'], $argv, true)
);

if ($is_cli_cron) {
    clear_buffers();
    @set_time_limit(0);
    try { init_pdo_with_dynamic_memory($config); } catch (Exception $e) {}
    
    $lock_handle = acquire_system_lock($backup_dir, 'backup', $config['lock_timeout']);
    if (!$lock_handle) {
        if ($is_cli_cron) {
            fwrite(STDERR, "ERROR: Islem zaten aktif.\n");
            exit(1);
        }
        json_response(false, "ERROR: Islem zaten aktif.", [], 409);
    }

    $pdo = null;
    $tmp_gz_file = null;
    $target_gz_file = null;

    try {
        SchemaCache::clear();
        $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
        check_sufficient_disk_space($pdo, $config['db_name'], $backup_dir);

        $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);

        $backup_time_string = gmdate('Y-m-d_H-i') . 'UTC';

        $base_gz_file = $backup_dir . '/' . $config['db_name'] . '_' . $backup_time_string;
        $target_gz_file = $base_gz_file . '.sql.gz';
        $dup_counter = 1;

        while (file_exists($target_gz_file)) {
            $target_gz_file = $base_gz_file . '_' . $dup_counter . '.sql.gz';
            $dup_counter++;
        }

        $tmp_gz_file = $target_gz_file . '.tmp';

        $gz_level = get_dynamic_system_load();
        $gz = gzopen($tmp_gz_file, "w{$gz_level}");
        if (!$gz) throw new Exception("Geçici sıkıştırılmış arşiv oluşturulamadı!");

        safe_gzwrite($gz, "-- MySQL Cron Backup\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n\n");

        foreach ($tables as $t) {
            update_system_lock_heartbeat($lock_handle);
            export_single_table_to_stream($pdo, $t, $gz, $config['db_name'], $config['backup_chunk'], $config['max_insert_rows']);
        }
        
        safe_gzwrite($gz, "\nSET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n");
        gzclose($gz);

        if (!@rename($tmp_gz_file, $target_gz_file)) {
            throw new Exception("Geçici gzip dosyası asıl hedefe taşınamadı!");
        }

        verify_and_checksum_gzip($target_gz_file);
        limit_backup_files($backup_dir, $config['max_backups']);
        
        if ($is_cli_cron) {
            echo "SUCCESS\n";
            exit(0);
        }
        json_response(true, "SUCCESS");
    } catch (Exception $e) {
        Logger::error("Cron yedekleme hatası: " . $e->getMessage());
        safe_transaction_rollback($pdo);
        if (isset($tmp_gz_file) && is_file($tmp_gz_file)) unlink($tmp_gz_file);
        if (isset($target_gz_file) && is_file($target_gz_file)) {
            try {
                $real_target = validate_path_safe($target_gz_file, $backup_dir);
                unlink($real_target);
            } catch (Exception $exPath) {}
        }
        if ($is_cli_cron) {
            fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
            exit(1);
        }
        json_response(false, "ERROR: " . $e->getMessage(), [], 500);
    } finally {
        release_system_lock($lock_handle);
    }
    exit;
}

// ==========================================
// 7. OTURUM YÖNETİMİ VE BRUTE-FORCE KORUMASI
// ==========================================
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

if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();
    header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
    exit;
}

if (!isset($_SESSION['login_attempts'])) $_SESSION['login_attempts'] = 0;

$is_locked = false;
$remaining_time = 0;

if (isset($_SESSION['lockout_until'])) {
    if (time() < $_SESSION['lockout_until']) {
        $is_locked = true;
        $remaining_time = $_SESSION['lockout_until'] - time();
    } else {
        unset($_SESSION['lockout_until']);
        $_SESSION['login_attempts'] = 0;
    }
}

if (isset($_POST['username'], $_POST['password'])) {
    $login_csrf = $_POST['csrf_token'] ?? '';
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $login_csrf)) {
        Logger::warning("Geçersiz CSRF giriş denemesi. IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'));
        $err = "Geçersiz CSRF Token!";
    } elseif ($is_locked) {
        $err = "Çok fazla hatalı giriş denemesi!";
    } else {
        $user_captcha = (int)($_POST['captcha'] ?? 0);
        $correct_captcha = (int)($_SESSION['captcha_ans'] ?? -1);

        if ($user_captcha !== $correct_captcha) {
            Logger::warning("Hatalı Captcha girişi. IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'));
            $err = "Güvenlik sorusu yanıtı hatalı!";
        } elseif (
            hash_equals($config['auth_user'], $_POST['username']) && 
            hash_equals($config['auth_pass'], $_POST['password'])
        ) {
            $_SESSION['logged_in'] = true;
            $_SESSION['login_attempts'] = 0;
            unset($_SESSION['lockout_until'], $_SESSION['captcha_ans']);
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            session_regenerate_id(true);
            Logger::info("Başarılı kullanıcı girişi yapıldı.");
            header('Location: ' . strtok($_SERVER["REQUEST_URI"], '?'));
            exit;
        } else {
            $_SESSION['login_attempts']++;
            Logger::warning("Başarısız kullanıcı adı/şifre denemesi ({$_SESSION['login_attempts']}. deneme). IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'));
            if ($_SESSION['login_attempts'] >= $config['max_login_attempts']) {
                $_SESSION['lockout_until'] = time() + $config['lockout_time'];
                $is_locked = true;
                $remaining_time = $config['lockout_time'];
                $err = "5 kez hatalı giriş yapıldı! 15 dakika engellendiniz.";
            } else {
                $rem = $config['max_login_attempts'] - $_SESSION['login_attempts'];
                $err = "Hatalı giriş! Kalan hakkınız: {$rem}";
            }
        }
    }
}

$num1 = random_int(1, 15);
$num2 = random_int(1, 15);
$_SESSION['captcha_ans'] = $num1 + $num2;

if (!isset($_SESSION['logged_in'])) { 
    clear_buffers();
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Giriş Yap | VEDO MYSQL BACKUP</title>
    <style nonce="<?=$nonce?>">
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #0b0f19; color: #c9d1d9; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .login-card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; width: 100%; max-width: 380px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
        h3 { text-align: center; margin-bottom: 20px; font-size: 1.2rem; color: #f9fafb; font-weight: 700; letter-spacing: -0.5px; }
        .alert { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; padding: 10px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 16px; text-align: center; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 0.8rem; color: #9ca3af; margin-bottom: 6px; font-weight: 500; }
        input[type="text"], input[type="password"], input[type="number"] { width: 100%; padding: 10px 12px; background: #0b0f19; border: 1px solid #374151; border-radius: 6px; color: #f9fafb; font-size: 0.9rem; outline: none; transition: 0.2s; }
        input:focus { border-color: #3b82f6; box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2); }
        .btn-submit { width: 100%; padding: 10px; background: #10b981; border: none; border-radius: 6px; color: #fff; font-weight: 600; cursor: pointer; transition: 0.2s; }
        .btn-submit:hover { background: #059669; }
    </style>
</head>
<body>
    <div class="login-card">
        <h3>VEDO MYSQL BACKUP</h3>
        <?=isset($err) ? "<div class='alert'>".htmlspecialchars($err, ENT_QUOTES, 'UTF-8')."</div>" : ""?>
        
        <?php if ($is_locked): ?>
            <div class="alert">Güvenlik Engeli!<br>Kalan Süre: <strong id="cd"><?=$remaining_time?></strong> sn</div>
            <script nonce="<?=$nonce?>">
                let t = <?=$remaining_time?>;
                setInterval(() => { t--; if (t<=0) location.reload(); else document.getElementById('cd').innerText = t; }, 1000);
            </script>
        <?php else: ?>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?=$_SESSION['csrf_token']?>">
                <div class="form-group">
                    <label>Kullanıcı Adı</label>
                    <input type="text" name="username" required autocomplete="off">
                </div>
                <div class="form-group">
                    <label>Şifre</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label>Güvenlik Sorusu: <strong><?=$num1?> + <?=$num2?> = ?</strong></label>
                    <input type="number" name="captcha" required>
                </div>
                <button type="submit" class="btn-submit">Giriş Yap</button>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
<?php exit; }

try { init_pdo_with_dynamic_memory($config); } catch (Exception $e) {}

// ==========================================
// 8. AJAX / API ARKA PLAN İŞLEMLERİ
// ==========================================
$action = $_POST['action'] ?? $_GET['action'] ?? '';

if (!empty($action)) {
    clear_buffers();

    $client_csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $client_csrf)) {
        Logger::warning("CSRF doğrulaması başarısız! Eylem: {$action}");
        if ($action === 'download_backup') {
            if (php_sapi_name() === 'cli') exit(1);
            http_response_code(403);
            die("Geçersiz CSRF Token!");
        }
        json_response(false, "Geçersiz CSRF Token! İşlem reddedildi.", [], 403);
    }

    $allowed_actions = [
        'get_live_metrics', 'get_tables', 'backup_table', 
        'finalize_backup', 'clear_db', 'prepare_restore', 
        'execute_chunks', 'delete_selected', 'delete_batch', 'download_backup'
    ];

    if (!in_array($action, $allowed_actions, true)) {
        json_response(false, "Erişim Engellendi: İzin verilmeyen eylem!", [], 405);
    }

    session_write_close();

    $mem_usage = memory_get_usage(true);
    $mem_peak = memory_get_peak_usage(true);

    switch ($action) {

        case 'download_backup':
            $filename = basename(urldecode($_POST['file'] ?? $_GET['file'] ?? ''));
            if (empty($filename) || !str_ends_with($filename, '.sql.gz')) {
                if (php_sapi_name() === 'cli') exit(1);
                http_response_code(400);
                die("Geçersiz dosya!");
            }
            
            try {
                $real_file = validate_path_safe($backup_dir . '/' . $filename, $backup_dir);
            } catch (Exception $e) {
                if (php_sapi_name() === 'cli') exit(1);
                http_response_code(403);
                die("Güvenlik ihlali engellendi!");
            }

            clear_buffers();
            $file_size = filesize($real_file);
            $start = 0;
            $end = $file_size - 1;
            $status_code = 200;

            if (isset($_SERVER['HTTP_RANGE'])) {
                if (preg_match('/bytes=(\d+)-(\d+)?/', $_SERVER['HTTP_RANGE'], $range_matches)) {
                    $start = (int)$range_matches[1];
                    if (!empty($range_matches[2])) {
                        $end = (int)$range_matches[2];
                    }

                    if ($start > $end || $start >= $file_size || $end >= $file_size) {
                        header('HTTP/1.1 416 Requested Range Not Satisfiable');
                        header("Content-Range: bytes */{$file_size}");
                        exit;
                    }
                    $status_code = 206;
                }
            }

            $length = $end - $start + 1;

            if ($status_code === 206) {
                header('HTTP/1.1 206 Partial Content');
                header("Content-Range: bytes {$start}-{$end}/{$file_size}");
            }

            header('Content-Description: File Transfer');
            header('Content-Type: application/gzip');
            header('Content-Disposition: attachment; filename="' . basename($real_file) . '"');
            header('Content-Length: ' . $length);
            header('Accept-Ranges: bytes');
            header('Pragma: public');
            header('Expires: 0');
            header('Cache-Control: must-revalidate, post-check=0, pre-check=0');

            $fp = fopen($real_file, 'rb');
            if ($fp !== false) {
                if ($start > 0) {
                    fseek($fp, $start);
                }
                $bytes_sent = 0;
                while (!feof($fp) && $bytes_sent < $length && connection_status() === 0) {
                    $read_bytes = min(262144, $length - $bytes_sent);
                    $buffer = fread($fp, $read_bytes);
                    if ($buffer === false || $buffer === '') break;
                    echo $buffer;
                    flush();
                    $bytes_sent += strlen($buffer);
                }
                fclose($fp);
            }
            exit;

        case 'get_live_metrics':
            $cpu_load = 0;
            $server_ram_total_mb = 0;
            $server_ram_used_mb = 0;
            $server_ram_pct = 0;

            if (function_exists('sys_getloadavg')) {
                $loads = sys_getloadavg();
                if (is_array($loads) && isset($loads[0])) {
                    static $core_count = null;
                    if ($core_count === null) {
                        $core_count = 1;
                        if (is_readable('/proc/cpuinfo')) {
                            $cpu_info = file_get_contents('/proc/cpuinfo');
                            if ($cpu_info !== false) {
                                $core_count = max(1, substr_count($cpu_info, 'processor'));
                            }
                        }
                    }
                    $cpu_load = round(($loads[0] / $core_count) * 100, 1);
                }
            }

            if (is_readable('/proc/meminfo')) {
                $meminfo = file_get_contents('/proc/meminfo');
                if ($meminfo !== false) {
                    $mem_total = preg_match('/MemTotal:\s+(\d+)\s+kB/i', $meminfo, $m_tot) ? (int)$m_tot[1] * 1024 : 0;
                    if (preg_match('/MemAvailable:\s+(\d+)\s+kB/i', $meminfo, $m_av)) {
                        $mem_avail = (int)$m_av[1] * 1024;
                    } else {
                        $mem_free = preg_match('/MemFree:\s+(\d+)\s+kB/i', $meminfo, $m_fr) ? (int)$m_fr[1] * 1024 : 0;
                        $buffers = preg_match('/Buffers:\s+(\d+)\s+kB/i', $meminfo, $m_buf) ? (int)$m_buf[1] * 1024 : 0;
                        $cached = preg_match('/Cached:\s+(\d+)\s+kB/i', $meminfo, $m_cac) ? (int)$m_cac[1] * 1024 : 0;
                        $mem_avail = $mem_free + $buffers + $cached;
                    }

                    if ($mem_total > 0) {
                        $server_ram_total_mb = round($mem_total / 1024 / 1024, 2);
                        $used_bytes = max(0, $mem_total - $mem_avail);
                        $server_ram_used_mb = round($used_bytes / 1024 / 1024, 2);
                        $server_ram_pct = round(($used_bytes / $mem_total) * 100, 1);
                    }
                }
            } elseif (PHP_OS_FAMILY === 'Windows') {
                $ps_out = [];
                $exit_code = 1;
                $available_bytes = 0;

if (function_exists('exec')) {

    $ps_out = [];
    $exit_code = 1;

           @exec(
               'powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory"',
               $ps_out,
               $exit_code
            );

           if ($exit_code === 0 && !empty($ps_out) && is_numeric(trim($ps_out[0] ?? ''))) {
               $available_bytes = (int)trim($ps_out[0]) * 1024;
            }
        }
                if ($exit_code === 0 && !empty($ps_out)) {
                    $json_str = implode('', $ps_out);
                    $win_mem = json_decode($json_str, true);
                    if (is_array($win_mem) && isset($win_mem['TotalVisibleMemorySize'], $win_mem['FreePhysicalMemory'])) {
                        $tot_bytes = (int)$win_mem['TotalVisibleMemorySize'] * 1024;
                        $free_bytes = (int)$win_mem['FreePhysicalMemory'] * 1024;
                        $used_b = $tot_bytes - $free_bytes;
                        $server_ram_total_mb = round($tot_bytes / 1024 / 1024, 2);
                        $server_ram_used_mb = round($used_b / 1024 / 1024, 2);
                        $server_ram_pct = round(($used_b / $tot_bytes) * 100, 1);
                    }
                }
            }

            if ($server_ram_total_mb <= 0) {
                $server_ram_used_mb = round(memory_get_usage(true) / 1024 / 1024, 2);
                $mem_limit_str = $config['memory_limit'];
                $calc_total = (int)$mem_limit_str;
                if (str_contains(strtoupper($mem_limit_str), 'G')) $calc_total *= 1024;
                $server_ram_total_mb = max(512, $calc_total);
                $server_ram_pct = round(($server_ram_used_mb / $server_ram_total_mb) * 100, 1);
            }

            $total_disk_sp = disk_total_space(__DIR__);
            $free_disk_sp = disk_free_space(__DIR__);
            $disk_pct = ($total_disk_sp !== false && $free_disk_sp !== false) ? round((($total_disk_sp - $free_disk_sp) / $total_disk_sp) * 100, 1) : 0;

            $db_live_tables = 0;
            $db_live_rows = 0;
            $db_live_size_bytes = 0;
            try {
                $pdo_metrics = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
                $stmtM = $pdo_metrics->prepare("SELECT COUNT(*) as tc, COALESCE(SUM(TABLE_ROWS), 0) as rc, COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) as ts FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?");
                $stmtM->execute([$config['db_name']]);
                $resM = $stmtM->fetch();
                if ($resM) {
                    $db_live_tables = (int)($resM['tc'] ?? 0);
                    $db_live_rows = (int)($resM['rc'] ?? 0);
                    $db_live_size_bytes = (int)($resM['ts'] ?? 0);
                }
            } catch (Exception $exM) {}

            json_response(true, 'Metrikler alındı', [
                'cpu' => max(0, min(100, $cpu_load)),
                'ram' => round(memory_get_usage(true) / 1024 / 1024, 2),
                'ram_total' => $server_ram_total_mb,
                'server_ram_used' => $server_ram_used_mb,
                'ram_pct' => max(0, min(100, $server_ram_pct)),
                'disk' => $disk_pct,
                'db_tables' => $db_live_tables,
                'db_rows' => number_format($db_live_rows),
                'db_size' => format_bytes($db_live_size_bytes),
                'db_raw_bytes' => $db_live_size_bytes
            ]);

        case 'get_tables':
            $panel_lock_handle = acquire_system_lock($backup_dir, 'backup', $config['lock_timeout']);
            if (!$panel_lock_handle) {
                json_response(false, 'Şu anda başka bir yedekleme aktif. Lütfen bekleyin.', [], 409);
            }

            try {
                SchemaCache::clear();
                $pdo = init_pdo_with_dynamic_memory($config);
                check_sufficient_disk_space($pdo, $config['db_name'], $backup_dir);

                $tables = $pdo->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);

                $tmp = $config['db_name'] . '_' . gmdate('Y-m-d_H-i-s') . 'UTC.sql.gz.tmp';
                $gz_level = get_dynamic_system_load();
                $gz = gzopen($backup_dir . '/' . $tmp, "w{$gz_level}");
                if ($gz) {
                    safe_gzwrite($gz, "-- VEDO MYSQL BACKUP\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n\n");
                    gzclose($gz);
                }
                
                json_response(true, 'Tablo listesi hazırlandı', [
                    'tables' => $tables, 
                    'tmp_file' => $tmp,
                    'db_raw_bytes' => get_database_size_bytes($pdo, $config['db_name']),
                    'mem_usage' => format_bytes($mem_usage),
                    'mem_peak' => format_bytes($mem_peak)
                ]);
            } catch (Exception $e) {
                Logger::error("get_tables hatası: " . $e->getMessage());
                json_response(false, $e->getMessage(), [], 500);
            } finally {
                release_system_lock($panel_lock_handle);
            }

        case 'backup_table':
            $pdo = null;
            $gz_tmp = null;
            $lock_handle = acquire_system_lock($backup_dir, 'backup', $config['lock_timeout']);
            try {
                $requested_table = $_POST['table'] ?? '';
                if (!preg_match('/^[a-zA-Z0-9_]+$/', $requested_table)) throw new Exception("Geçersiz tablo adı!");

                $pdo = init_pdo_with_dynamic_memory($config);
                $tmp_path = validate_path_safe($backup_dir . '/' . basename($_POST['tmp_file']), $backup_dir);
                
                $gz_level = get_dynamic_system_load();
                $gz_tmp = gzopen($tmp_path, "a{$gz_level}");
                if (!$gz_tmp) throw new Exception("Geçici arşiv dosyası açılamadı!");

                update_system_lock_heartbeat($lock_handle);
                export_single_table_to_stream($pdo, $requested_table, $gz_tmp, $config['db_name'], $config['backup_chunk'], $config['max_insert_rows']);

                gzclose($gz_tmp);
                $current_bytes = file_exists($tmp_path) ? filesize($tmp_path) : 0;

                json_response(true, "`{$requested_table}` tablosu yedeklendi.", [
                    'bytes_written' => $current_bytes,
                    'mem_usage' => format_bytes(memory_get_usage(true)),
                    'mem_peak' => format_bytes(memory_get_peak_usage(true))
                ]);
            } catch (Exception $e) {
                Logger::error("backup_table hatası: " . $e->getMessage());
                if (isset($gz_tmp) && is_resource($gz_tmp)) gzclose($gz_tmp);
                safe_transaction_rollback($pdo);
                json_response(false, $e->getMessage(), [], 500);
            } finally {
                release_system_lock($lock_handle);
            }

        case 'finalize_backup':
            $tmp = null;
            $gz_f = null;
            $lock_handle = acquire_system_lock($backup_dir, 'backup', $config['lock_timeout']);
            try {
                $tmp = validate_path_safe($backup_dir . '/' . basename($_POST['tmp_file']), $backup_dir);
                $gz_f = preg_replace('/\.tmp$/i', '', $tmp);
                
                $gz_level = get_dynamic_system_load();
                $gz_app = gzopen($tmp, "a{$gz_level}");
                if ($gz_app) {
                    safe_gzwrite($gz_app, "\nSET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n");
                    gzclose($gz_app);
                }
                
                $compressed_size = filesize($tmp);

                if (!@rename($tmp, $gz_f)) {
                    throw new Exception("Geçici dosya yeniden adlandırılamadı!");
                }
                
                $hash = verify_and_checksum_gzip($gz_f);
                limit_backup_files($backup_dir, $config['max_backups']);

                $filename = basename($gz_f);
                $filemtime = filemtime($gz_f);

                json_response(true, 'Yedek tamamlandı ve doğrulandı. SHA256: ' . substr($hash, 0, 10) . '...', [
                    'compressed_size' => format_bytes($compressed_size),
                    'new_backup' => [
                        'name' => $filename,
                        'size' => format_bytes($compressed_size),
                        'bytes' => $compressed_size,
                        'date' => date('Y-m-d H:i:s', $filemtime)
                    ]
                ]);
            } catch (Exception $e) {
                Logger::error("finalize_backup hatası: " . $e->getMessage());
                if (isset($tmp) && is_file($tmp)) unlink($tmp);
                if (isset($gz_f) && is_file($gz_f)) {
                    try {
                        $real_gz = validate_path_safe($gz_f, $backup_dir);
                        unlink($real_gz);
                    } catch (Exception $exP) {}
                }
                json_response(false, 'Bütünlük hatası: ' . $e->getMessage(), [], 500);
            } finally {
                release_system_lock($lock_handle);
            }

        case 'clear_db':
            $restore_lock_handle = acquire_system_lock($backup_dir, 'restore', $config['lock_timeout']);
            if (!$restore_lock_handle) {
                json_response(false, 'Başka bir restore/temizleme aktif. İşlem reddedildi!', [], 409);
            }

            try {
                SchemaCache::clear();
                $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
                $pdo->exec("SET FOREIGN_KEY_CHECKS=0;");

                $events = $pdo->query("SHOW EVENTS WHERE Db = '{$config['db_name']}'")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($events as $ev) {
                    $name = $ev['Name'] ?? '';
                    if (preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
                        $pdo->exec("DROP EVENT IF EXISTS `$name`");
                    }
                }

                $trigs = $pdo->query("SHOW TRIGGERS")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($trigs as $tr) {
                    $name = $tr['Trigger'] ?? '';
                    if (preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
                        $pdo->exec("DROP TRIGGER IF EXISTS `$name`");
                    }
                }

                $views = $pdo->query("SHOW FULL TABLES WHERE Table_type = 'VIEW'")->fetchAll(PDO::FETCH_COLUMN);
                foreach ($views as $v) {
                    if (preg_match('/^[a-zA-Z0-9_]+$/', $v)) {
                        $pdo->exec("DROP VIEW IF EXISTS `$v`");
                    }
                }

                $tables = $pdo->query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")->fetchAll(PDO::FETCH_COLUMN);
                foreach ($tables as $t) {
                    if (preg_match('/^[a-zA-Z0-9_]+$/', $t)) {
                        $pdo->exec("DROP TABLE IF EXISTS `$t`");
                    }
                }

                $funcs = $pdo->query("SHOW FUNCTION STATUS WHERE Db = '{$config['db_name']}'")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($funcs as $fn) {
                    $name = $fn['Name'] ?? '';
                    if (preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
                        $pdo->exec("DROP FUNCTION IF EXISTS `$name`");
                    }
                }

                $procs = $pdo->query("SHOW PROCEDURE STATUS WHERE Db = '{$config['db_name']}'")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($procs as $pr) {
                    $name = $pr['Name'] ?? '';
                    if (preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
                        $pdo->exec("DROP PROCEDURE IF EXISTS `$name`");
                    }
                }

                $pdo->exec("SET FOREIGN_KEY_CHECKS=1;");
                SchemaCache::clear();
                Logger::info("Veritabanı tamamen sıfırlandı.");
                json_response(true, 'Veritabanı tüm bağımlılıklarıyla sıfırlandı.');
            } catch (Exception $e) {
                Logger::error("clear_db hatası: " . $e->getMessage());
                json_response(false, $e->getMessage(), [], 500);
            } finally {
                release_system_lock($restore_lock_handle);
            }

        case 'prepare_restore':
            $filename = basename(urldecode($_POST['file'] ?? ''));
            try {
                $file = validate_path_safe($backup_dir . '/' . $filename, $backup_dir);
            } catch (Exception $e) {
                json_response(false, 'Geçersiz dosya!', [], 400);
            }

            if (!is_file($file) || !str_ends_with($file, '.sql.gz')) {
                json_response(false, 'Geçersiz dosya biçimi!', [], 400);
            }

            try {
                SchemaCache::clear();
                $file_sha = verify_backup_checksum($file);
                $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);

                $gz = gzopen($file, 'rb');
                $tables_in_backup = [];
                while (!gzeof($gz)) {
                    $line = gzgets($gz, VEDO_LINE_MAX_BUFFER);
                    if ($line !== false && preg_match('/^DROP TABLE IF EXISTS `([^`]+)`;/i', $line, $m)) {
                        if (preg_match('/^[a-zA-Z0-9_]+$/', $m[1])) {
                            $tables_in_backup[] = $m[1];
                        }
                    }
                }
                gzclose($gz);

                $total_tables = count($tables_in_backup);
                $total_bytes = filesize($file);

                $checkpoint_file = $backup_dir . '/' . md5($filename) . '.progress.json';
                $resumed_offset = 0;
                $resumed_tables = 0;
                $resumed_rows = 0;

                if (is_file($checkpoint_file)) {
                    $cp_data = json_decode((string)file_get_contents($checkpoint_file), true);
                    if (is_array($cp_data) && isset($cp_data['offset'], $cp_data['file'], $cp_data['sha256']) 
                        && $cp_data['file'] === $filename && hash_equals($cp_data['sha256'], $file_sha)) {
                        $resumed_offset = (int)$cp_data['offset'];
                        $resumed_tables = (int)$cp_data['processed_tables'];
                        $resumed_rows = (int)$cp_data['processed_rows'];
                    } else {
                        $bak_file = $checkpoint_file . '.bak';
                        if (is_file($bak_file)) {
                            $bak_data = json_decode((string)file_get_contents($bak_file), true);
                            if (is_array($bak_data) && isset($bak_data['offset']) && $bak_data['file'] === $filename) {
                                $resumed_offset = (int)$bak_data['offset'];
                                $resumed_tables = (int)$bak_data['processed_tables'];
                                $resumed_rows = (int)$bak_data['processed_rows'];
                            }
                        }
                    }
                }

                json_response(true, 'Geri yükleme hazırlandı', [
                    'file_sha256' => $file_sha,
                    'total_tables' => $total_tables,
                    'total_bytes' => $total_bytes,
                    'resumed_offset' => $resumed_offset,
                    'resumed_tables' => $resumed_tables,
                    'resumed_rows' => $resumed_rows
                ]);
            } catch (Exception $e) {
                json_response(false, $e->getMessage(), [], 500);
            }

        case 'execute_chunks':
            $filename = basename(urldecode($_POST['file'] ?? ''));
            try {
                $file = validate_path_safe($backup_dir . '/' . $filename, $backup_dir);
            } catch (Exception $e) {
                json_response(false, 'Geçersiz dosya!', [], 400);
            }

            $checkpoint_file = $backup_dir . '/' . md5($filename) . '.progress.json';

            $byte_offset = (int)($_POST['offset'] ?? 0);
            $processed_tables_count = (int)($_POST['processed_tables'] ?? 0);
            $processed_rows_count = (int)($_POST['processed_rows'] ?? 0);

            $query_buffer = '';
            $in_string = false;
            $string_char = '';
            $in_comment_multi = false;
            $in_comment_single = false;
            $escaped = false;
            $current_delimiter = ';';

            $file_sha = '';
            if (is_file($file)) {
                $sha_file = $file . '.sha256';
                if (is_file($sha_file)) {
                    $file_sha = trim(explode(' ', (string)file_get_contents($sha_file))[0] ?? '');
                }
            }

            if (is_file($checkpoint_file)) {
                $cp_data = json_decode((string)file_get_contents($checkpoint_file), true);
                if (is_array($cp_data) && isset($cp_data['offset'], $cp_data['file']) && $cp_data['file'] === $filename) {
                    if (empty($cp_data['sha256']) || hash_equals($cp_data['sha256'], $file_sha)) {
                        if ($byte_offset === 0 || $byte_offset === (int)$cp_data['offset']) {
                            $byte_offset = (int)$cp_data['offset'];
                            $processed_tables_count = (int)$cp_data['processed_tables'];
                            $processed_rows_count = (int)$cp_data['processed_rows'];
                            
                            $query_buffer      = $cp_data['query_buffer'] ?? '';
                            $in_string         = (bool)($cp_data['in_string'] ?? false);
                            $string_char       = $cp_data['string_char'] ?? '';
                            $in_comment_multi  = (bool)($cp_data['in_comment_multi'] ?? false);
                            $in_comment_single = (bool)($cp_data['in_comment_single'] ?? false);
                            $escaped           = (bool)($cp_data['escaped'] ?? false);
                            $current_delimiter = $cp_data['current_delimiter'] ?? ';';
                        }
                    }
                }
            }
            
            $chunk_lock_handle = acquire_system_lock($backup_dir, 'restore', $config['lock_timeout']);
            if (!$chunk_lock_handle) {
                json_response(false, 'Kilit alınamadı! Başka bir işlem yürütülüyor.', [], 409);
            }

            if (!is_file($file) || !str_ends_with($file, '.sql.gz')) {
                release_system_lock($chunk_lock_handle);
                json_response(false, 'Geçersiz dosya!', [], 400);
            }

            if ($byte_offset === 0) {
                try {
                    verify_backup_checksum($file);
                } catch (Exception $e) {
                    release_system_lock($chunk_lock_handle);
                    json_response(false, 'Geri yükleme reddedildi! ' . $e->getMessage(), [], 422);
                }
            }

            $pdo = null;
            try {
                $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
                
                $pdo->exec("SET FOREIGN_KEY_CHECKS=0;");
                $pdo->exec("SET UNIQUE_CHECKS=0;");

                $gz = gzopen($file, 'rb');
                if ($byte_offset > 0) {
                    gzseek($gz, $byte_offset);
                }

                $bytes_processed_in_chunk = 0;
                $max_bytes_per_chunk = (int)$config['restore_chunk']; 
                if ($max_bytes_per_chunk <= 0) $max_bytes_per_chunk = VEDO_RESTORE_CHUNK_BYTES;
                
                $executed_queries_count = 0;
                $chunk_read_size = (int)($config['read_chunk'] ?? VEDO_READ_CHUNK_BYTES);

                while (!gzeof($gz)) {
                    update_system_lock_heartbeat($chunk_lock_handle);
                    $buffer = restore_read_chunk($gz, $chunk_read_size, $bytes_processed_in_chunk);
                    if ($buffer === false) break;

                    $extracted_queries = restore_parse_buffer(
                        $buffer, 
                        $query_buffer, 
                        $in_string, 
                        $string_char, 
                        $in_comment_multi, 
                        $in_comment_single, 
                        $escaped, 
                        $current_delimiter
                    );

                    if (!empty($extracted_queries)) {
                        $executed_queries_count += restore_execute_sql($pdo, $extracted_queries, $processed_tables_count, $processed_rows_count, $backup_dir, $config);
                    }

                    if ($bytes_processed_in_chunk >= $max_bytes_per_chunk && empty(trim($query_buffer)) && !$in_string && !$in_comment_multi) {
                        break;
                    }
                }

                $new_byte_offset = gztell($gz);
                $is_eof = gzeof($gz);
                gzclose($gz);

                if (memory_get_usage(true) > (128 * 1024 * 1024)) {
                    gc_collect_cycles();
                }

                if (!$is_eof) {
                    $checkpoint_tmp_file = $checkpoint_file . '.tmp';
                    $safe_qbuf = (strlen($query_buffer) > 1048576) ? substr($query_buffer, 0, 1048576) : $query_buffer;

                    $checkpoint_data = json_encode([
                        'file'              => $filename,
                        'offset'            => $new_byte_offset,
                        'processed_tables'  => $processed_tables_count,
                        'processed_rows'    => $processed_rows_count,
                        'sha256'            => $file_sha,
                        'query_buffer'      => $safe_qbuf,
                        'in_string'         => $in_string,
                        'string_char'       => $string_char,
                        'in_comment_multi'  => $in_comment_multi,
                        'in_comment_single' => $in_comment_single,
                        'escaped'           => $escaped,
                        'current_delimiter' => $current_delimiter,
                        'updated_at'        => time()
                    ], JSON_UNESCAPED_UNICODE);

                    if (is_file($checkpoint_file)) {
                        copy($checkpoint_file, $checkpoint_file . '.bak');
                    }

                    if (safe_file_put_contents($checkpoint_tmp_file, $checkpoint_data, LOCK_EX)) {
                        if (!@rename($checkpoint_tmp_file, $checkpoint_file)) {
                            throw new Exception("Kritik: Checkpoint dosyası güncellenemedi! İşlem durduruldu.");
                        }
                    }
                } else {
                    if (!empty(trim($query_buffer))) {
                        restore_execute_sql($pdo, [$query_buffer], $processed_tables_count, $processed_rows_count, $backup_dir, $config);
                    }

                    $pdo->exec("SET UNIQUE_CHECKS=1;");
                    $pdo->exec("SET FOREIGN_KEY_CHECKS=1;");

                    if (is_file($checkpoint_file)) unlink($checkpoint_file);
                    if (is_file($checkpoint_file . '.bak')) unlink($checkpoint_file . '.bak');

                    $integrity_report = verify_database_integrity_after_restore($pdo, $config['db_name'], true);
                    Logger::info("Restore Başarılı. Rapor: " . json_encode($integrity_report));
                }

                json_response(true, $is_eof ? 'Geri yükleme tamamlandı.' : 'Parça işlendi.', [
                    'completed'        => $is_eof,
                    'new_offset'       => $new_byte_offset,
                    'processed_tables' => $processed_tables_count,
                    'processed_rows'   => $processed_rows_count,
                    'integrity'        => $is_eof ? ($integrity_report ?? null) : null
                ]);

            } catch (Exception $e) {
                Logger::error("execute_chunks hatası: " . $e->getMessage());
                json_response(false, $e->getMessage(), [], 500);
            } finally {
                release_system_lock($chunk_lock_handle);
            }

        case 'delete_selected':
            $filename = basename(urldecode($_POST['file'] ?? ''));
            try {
                $file = validate_path_safe($backup_dir . '/' . $filename, $backup_dir);
            } catch (Exception $e) {
                json_response(false, 'Güvenlik ihlali engellendi!', [], 403);
            }

            if (is_file($file)) {
                if (!unlink($file)) {
                    Logger::error("Dosya silinemedi: " . $file);
                    json_response(false, 'Yedek dosyası silinemedi!', [], 500);
                }
                
                $sha_file = $file . '.sha256';
                if (is_file($sha_file)) unlink($sha_file);

                $cp_file = $backup_dir . '/' . md5($filename) . '.progress.json';
                if (is_file($cp_file)) unlink($cp_file);

                Logger::info("Yedek dosyası silindi: " . $filename);
                json_response(true, 'Yedek dosyası başarıyla silindi.');
            } else {
                json_response(false, 'Silinecek dosya bulunamadı!', [], 404);
            }

        case 'delete_batch':
            $files = $_POST['files'] ?? [];
            if (!is_array($files) || empty($files)) {
                json_response(false, 'Silinecek dosya seçilmedi!', [], 400);
            }
            $deleted_count = 0;
            foreach ($files as $fn) {
                $filename = basename(urldecode((string)$fn));
                try {
                    $file = validate_path_safe($backup_dir . '/' . $filename, $backup_dir);
                    if (is_file($file)) {
                        @unlink($file);
                        $sha_file = $file . '.sha256';
                        if (is_file($sha_file)) @unlink($sha_file);
                        $cp_file = $backup_dir . '/' . md5($filename) . '.progress.json';
                        if (is_file($cp_file)) @unlink($cp_file);
                        $deleted_count++;
                    }
                } catch (Exception $e) {
                    Logger::warning("Toplu silmede hata: " . $e->getMessage());
                }
            }
            Logger::info("Toplu silme gerçekleştirildi. Silinen dosya sayısı: " . $deleted_count);
            json_response(true, "Toplu silme başarılı! {$deleted_count} adet yedek dosyası silindi.", ['deleted' => $deleted_count]);

        default:
            json_response(false, 'Bilinmeyen işlem!', [], 400);
    }
}

// ==========================================
// 9. ARAYÜZ KONTROL VE LİSTELEME
// ==========================================
$backup_files = glob($backup_dir . '/*.sql.gz') ?: [];
usort($backup_files, fn($a, $b) => filemtime($b) <=> filemtime($a));

$backups_list = [];
foreach ($backup_files as $f) {
    $fn = basename($f);
    $backups_list[] = [
        'name' => $fn,
        'size' => format_bytes(filesize($f)),
        'bytes' => filesize($f),
        'date' => date('Y-m-d H:i:s', filemtime($f)),
        'has_sha' => is_file($f . '.sha256')
    ];
}

$cron_url = '/usr/bin/php ' . __FILE__ . ' ' . $config['cron_token'];

$db_version = 'Bilinmiyor';
try {
    $pdo_v = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
    $db_version = $pdo_v->getAttribute(PDO::ATTR_SERVER_VERSION);
} catch (Exception $e) {}

clear_buffers();
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VEDO MYSQL BACKUP | Ultra Yönetim Paneli</title>
    <style nonce="<?=$nonce?>">
        :root {
            --bg-body: #0b0f19;
            --panel-bg: #111827;
            --panel-border: #1f2937;
            --text-main: #f9fafb;
            --text-sub: #9ca3af;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-body); color: var(--text-main); font-size: 13px; padding: 16px; line-height: 1.4; }
        .container { max-width: 1400px; margin: 0 auto; }
        
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--panel-border); }
        .brand { font-size: 1.15rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }
        .brand span { font-size: 0.7rem; background: var(--accent-blue); color: #fff; padding: 2px 8px; border-radius: 9999px; font-weight: 600; }
        .btn-logout { font-size: 0.75rem; color: var(--accent-red); text-decoration: none; border: 1px solid rgba(239, 68, 68, 0.3); padding: 5px 10px; border-radius: 6px; transition: 0.2s; font-weight: 600; }
        .btn-logout:hover { background: rgba(239, 68, 68, 0.1); }

        .metrics-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
        .m-card { background: var(--panel-bg); border: 1px solid var(--panel-border); border-radius: 8px; padding: 12px; }
        .m-head { font-size: 0.7rem; color: var(--text-sub); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; display: flex; justify-content: space-between; }
        .m-val { font-size: 1.1rem; font-weight: 700; color: #fff; margin-top: 4px; }
        .p-track { background: #1f2937; height: 6px; border-radius: 3px; margin-top: 8px; overflow: hidden; }
        .p-fill { background: var(--accent-blue); height: 100%; width: 0%; transition: width 0.3s ease; }

        .cron-box { background: #172033; border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 8px; padding: 10px 14px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
        .cron-title { font-size: 0.75rem; font-weight: 600; color: #60a5fa; }
        .cron-code { font-family: monospace; font-size: 0.75rem; color: #e0f2fe; background: #0b0f19; padding: 4px 8px; border-radius: 4px; border: 1px solid #1e293b; user-select: all; cursor: pointer; word-break: break-all; flex: 1; margin: 0 10px; }

        .sys-details { background: var(--panel-bg); border: 1px solid var(--panel-border); border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
        .sys-item { display: flex; flex-direction: column; }
        .sys-label { font-size: 0.7rem; color: var(--text-sub); font-weight: 600; text-transform: uppercase; }
        .sys-val { font-size: 0.85rem; font-weight: 600; color: #fff; margin-top: 2px; }

        .layout-grid { display: grid; grid-template-columns: 340px 1fr; gap: 16px; margin-bottom: 16px; }
        @media (max-width: 900px) { .layout-grid { grid-template-columns: 1fr; } }

        .panel { background: var(--panel-bg); border: 1px solid var(--panel-border); border-radius: 8px; padding: 14px; display: flex; flex-direction: column; }
        .p-title { font-size: 0.85rem; font-weight: 600; color: #fff; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }

        .btn-group { display: flex; flex-direction: column; gap: 8px; }
        .btn { border: none; border-radius: 6px; padding: 8px 12px; font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: 0.2s; color: #fff; display: inline-flex; align-items: center; justify-content: center; gap: 6px; text-decoration: none; width: 100%; }
        .btn-blue { background: var(--accent-blue); }
        .btn-blue:hover { background: #2563eb; }
        .btn-green { background: var(--accent-green); }
        .btn-green:hover { background: #059669; }
        .btn-red { background: var(--accent-red); }
        .btn-red:hover { background: #dc2626; }
        .btn-yellow { background: var(--accent-yellow); color: #000; }
        .btn-yellow:hover { background: #d97706; color: #fff; }
        .btn-sm { padding: 4px 8px; font-size: 0.75rem; width: auto; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .progress-box { margin-top: 12px; background: #0b0f19; border: 1px solid var(--panel-border); border-radius: 6px; padding: 10px; display: none; }
        .progress-text { font-size: 0.75rem; color: var(--text-sub); display: flex; justify-content: space-between; margin-bottom: 6px; }
        .progress-bar-wrap { background: #1f2937; height: 8px; border-radius: 4px; overflow: hidden; }
        .progress-bar-fill { background: var(--accent-green); height: 100%; width: 0%; transition: width 0.2s linear; }

        .eta-box { margin-top: 10px; background: #0b0f19; border: 1px solid var(--panel-border); border-radius: 6px; padding: 10px; font-size: 0.75rem; color: var(--text-sub); }
        .eta-box strong { color: #60a5fa; }

        .log-box { background: #050811; border: 1px solid var(--panel-border); border-radius: 6px; padding: 10px; font-family: monospace; font-size: 0.75rem; color: #34d399; height: 260px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

        .table-wrap { overflow-x: auto; background: var(--panel-bg); border: 1px solid var(--panel-border); border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 10px 14px; border-bottom: 1px solid var(--panel-border); }
        th { background: #0b0f19; color: var(--text-sub); font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.015); }

        .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 600; background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
        .badge-success { background: rgba(16, 185, 129, 0.15); color: #34d399; }
        
        .action-btns { display: flex; gap: 6px; }
        .checkbox-cell { width: 30px; text-align: center; }
        input[type="checkbox"] { accent-color: var(--accent-blue); cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                VEDO MYSQL BACKUP <span>v2.5 ULTRA</span>
            </div>
            <div>
                <a href="?logout=1" class="btn-logout">Çıkış Yap</a>
            </div>
        </header>

        <!-- Detaylı Sunucu Bilgileri -->
        <div class="sys-details">
            <div class="sys-item">
                <span class="sys-label">Sunucu İşletim Sistemi</span>
                <span class="sys-val"><?=PHP_OS_FAMILY?> (<?=php_uname('r')?>)</span>
            </div>
            <div class="sys-item">
                <span class="sys-label">PHP Sürümü</span>
                <span class="sys-val"><?=PHP_VERSION?></span>
            </div>
            <div class="sys-item">
                <span class="sys-label">MySQL Sürümü</span>
                <span class="sys-val"><?=htmlspecialchars($db_version)?></span>
            </div>
            <div class="sys-item">
                <span class="sys-label">Memory Limit (PHP)</span>
                <span class="sys-val"><?=$config['memory_limit']?></span>
            </div>
            <div class="sys-item">
                <span class="sys-label">Max Upload / Post</span>
                <span class="sys-val"><?=ini_get('upload_max_filesize')?> / <?=ini_get('post_max_size')?></span>
            </div>
            <div class="sys-item">
                <span class="sys-label">Zaman Dilimi</span>
                <span class="sys-val"><?=date_default_timezone_get()?></span>
            </div>
        </div>

        <!-- Canlı Metrikler (1s Güncelleme) -->
        <div class="metrics-bar">
            <div class="m-card">
                <div class="m-head"><span>CPU Kullanımı</span> <span id="m-cpu-pct">0%</span></div>
                <div class="m-val" id="m-cpu">0%</div>
                <div class="p-track"><div class="p-fill" id="m-cpu-fill"></div></div>
            </div>
            <div class="m-card">
                <div class="m-head"><span>Sistem RAM (MB / Yüzde)</span> <span id="m-ram-pct">0%</span></div>
                <div class="m-val" id="m-ram">0 MB / 0 MB</div>
                <div class="p-track"><div class="p-fill" id="m-ram-fill"></div></div>
            </div>
            <div class="m-card">
                <div class="m-head"><span>Disk Kullanımı</span> <span id="m-disk-pct">0%</span></div>
                <div class="m-val" id="m-disk">0%</div>
                <div class="p-track"><div class="p-fill" id="m-disk-fill"></div></div>
            </div>
            <div class="m-card">
                <div class="m-head"><span>Veritabanı Boyutu</span></div>
                <div class="m-val" id="m-db-size">0 MB</div>
                <div style="font-size: 0.7rem; color: var(--text-sub); margin-top: 4px;" id="m-db-info">0 Tablo | 0 Satır</div>
            </div>
        </div>

        <!-- Cron Bağlantı Kutusu -->
        <div class="cron-box">
            <span class="cron-title">Sunucu içerisinde otomatik yedek almak için CLI Cron Komutu:</span>
            <input type="text" readonly value="<?=htmlspecialchars($cron_url)?>" class="cron-code" id="cron-input" onclick="this.select()">
            <button class="btn btn-blue btn-sm" id="btn-copy-cron">Kopyala</button>
        </div>

        <!-- Ana Kontrol Panelleri -->
        <div class="layout-grid">
            <div class="panel">
                <div class="p-title">İşlem Merkezi</div>
                <div class="btn-group">
                    <button class="btn btn-green" id="btn-start-backup">Yedek Al (Sıkıştırılmış SQL)</button>
                    <button class="btn btn-red" id="btn-clear-db">Veritabanını Sıfırla (Temizle)</button>
                </div>

                <div class="progress-box" id="p-box">
                    <div class="progress-text">
                        <span id="p-status">İşleniyor...</span>
                        <span id="p-pct">0%</span>
                    </div>
                    <div class="progress-bar-wrap">
                        <div class="progress-bar-fill" id="p-fill"></div>
                    </div>
                </div>

                <div class="eta-box" id="eta-box">
                    <div>İşlenen Boyut: <strong id="eta-size">0 KB / 0 KB</strong></div>
                    <div>Anlık Hız: <strong id="eta-speed">0 KB/s</strong></div>
                    <div>Kalan Süre: <strong id="eta-time">--:--</strong></div>
                </div>
            </div>

            <div class="panel">
                <div class="p-title">Sistem Log Ekranı (Kalıcı Canlı Konsol)</div>
                <div class="log-box" id="log-console">[<?=date('H:i:s')?>] Sistem hazır. İşlem bekleniyor...</div>
            </div>
        </div>

        <!-- Yedek Dosyaları Listesi -->
        <div class="panel">
            <div class="p-title">
                <span>Mevcut Yedekler</span>
                <button class="btn btn-red btn-sm" id="btn-delete-batch" style="display: none;">Seçilenleri Sil</button>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th class="checkbox-cell"><input type="checkbox" id="select-all-backups"></th>
                            <th>Dosya Adı</th>
                            <th>Boyut</th>
                            <th>Tarih</th>
                            <th>Bütünlük (SHA256)</th>
                            <th>İşlemler</th>
                        </tr>
                    </thead>
                    <tbody id="backup-table-body">
                        <?php if (empty($backups_list)): ?>
                            <tr id="no-backup-row"><td colspan="6" style="text-align: center; color: var(--text-sub);">Henüz kaydedilmiş yedek bulunmuyor.</td></tr>
                        <?php else: foreach ($backups_list as $b): ?>
                            <tr data-file="<?=htmlspecialchars($b['name'])?>">
                                <td class="checkbox-cell"><input type="checkbox" class="backup-select" value="<?=htmlspecialchars($b['name'])?>"></td>
                                <td><strong><?=htmlspecialchars($b['name'])?></strong></td>
                                <td><?=$b['size']?></td>
                                <td><?=$b['date']?></td>
                                <td><?=$b['has_sha'] ? '<span class="badge badge-success">Doğrulandı</span>' : '<span class="badge">Eksik</span>'?></td>
                                <td>
                                    <div class="action-btns">
                                        <button class="btn btn-blue btn-sm btn-restore" data-file="<?=htmlspecialchars($b['name'])?>">Geri Yükle</button>
                                        <form method="POST" style="display:inline;">
                                            <input type="hidden" name="csrf_token" value="<?=$_SESSION['csrf_token']?>">
                                            <input type="hidden" name="action" value="download_backup">
                                            <input type="hidden" name="file" value="<?=htmlspecialchars($b['name'])?>">
                                            <button type="submit" class="btn btn-green btn-sm">İndir</button>
                                        </form>
                                        <button class="btn btn-red btn-sm btn-delete" data-file="<?=htmlspecialchars($b['name'])?>">Sil</button>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script nonce="<?=$nonce?>">
        const CSRF_TOKEN = '<?=$_SESSION['csrf_token']?>';
        
        // Log yazma fonksiyonu (Yazılar silinmez, kalıcı kalır)
        function appendLog(msg, type = 'info') {
            const consoleBox = document.getElementById('log-console');
            const time = new Date().toLocaleTimeString();
            let color = '#34d399';
            if (type === 'error') color = '#f87171';
            if (type === 'warn') color = '#fbbf24';
            
            const line = document.createElement('div');
            line.style.color = color;
            line.innerText = `[${time}] ${msg}`;
            consoleBox.appendChild(line);
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }

        // 1 Saniyede bir Anlık CPU/RAM Ölçümü
        function fetchLiveMetrics() {
            fetch('?action=get_live_metrics', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN)
            })
            .then(res => res.json())
            .then(res => {
                if (res.success) {
                    const d = res.data;
                    document.getElementById('m-cpu').innerText = d.cpu + '%';
                    document.getElementById('m-cpu-pct').innerText = d.cpu + '%';
                    document.getElementById('m-cpu-fill').style.width = d.cpu + '%';

                    document.getElementById('m-ram').innerText = d.server_ram_used + ' MB / ' + d.ram_total + ' MB';
                    document.getElementById('m-ram-pct').innerText = d.ram_pct + '%';
                    document.getElementById('m-ram-fill').style.width = d.ram_pct + '%';

                    document.getElementById('m-disk').innerText = d.disk + '%';
                    document.getElementById('m-disk-pct').innerText = d.disk + '%';
                    document.getElementById('m-disk-fill').style.width = d.disk + '%';

                    document.getElementById('m-db-size').innerText = d.db_size;
                    document.getElementById('m-db-info').innerText = d.db_tables + ' Tablo | ' + d.db_rows + ' Satır';
                }
            })
            .catch(() => {});
        }
        setInterval(fetchLiveMetrics, 1000);
        fetchLiveMetrics();

        // Cron URL Kopyalama
        document.getElementById('btn-copy-cron').addEventListener('click', function() {
            const input = document.getElementById('cron-input');
            input.select();
            navigator.clipboard.writeText(input.value);
            appendLog('CLI cron komutu panoya kopyalandı.', 'info');
        });

        // Toplu Seçim Checkbox İşlemleri
        const selectAll = document.getElementById('select-all-backups');
        const batchBtn = document.getElementById('btn-delete-batch');

        function updateBatchButton() {
            const checkedCount = document.querySelectorAll('.backup-select:checked').length;
            batchBtn.style.display = checkedCount > 0 ? 'inline-block' : 'none';
            batchBtn.innerText = `Seçilenleri Sil (${checkedCount})`;
        }

        selectAll.addEventListener('change', function() {
            document.querySelectorAll('.backup-select').forEach(cb => cb.checked = this.checked);
            updateBatchButton();
        });

        document.getElementById('backup-table-body').addEventListener('change', function(e) {
            if (e.target.classList.contains('backup-select')) {
                updateBatchButton();
            }
        });

        // İlerleme ve ETA Hesaplayıcı (KB Cinsinden)
        let startTime = 0;
        function updateProgressUI(processedBytes, totalBytes) {
            const pBox = document.getElementById('p-box');
            pBox.style.display = 'block';

            let pct = 0;
            if (totalBytes > 0) {
                pct = Math.min(100, Math.round((processedBytes / totalBytes) * 100));
            }
            document.getElementById('p-pct').innerText = pct + '%';
            document.getElementById('p-fill').style.width = pct + '%';

            const elapsed = (Date.now() - startTime) / 1000;
            const processedKB = processedBytes / 1024;
            const totalKB = totalBytes / 1024;
            
            let speedKBps = elapsed > 0 ? (processedKB / elapsed) : 0;
            let remainingKB = Math.max(0, totalKB - processedKB);
            let remainingSec = speedKBps > 0 ? Math.round(remainingKB / speedKBps) : 0;

            let min = Math.floor(remainingSec / 60);
            let sec = remainingSec % 60;
            let timeStr = (min < 10 ? '0' + min : min) + ':' + (sec < 10 ? '0' + sec : sec);

            document.getElementById('eta-size').innerText = Math.round(processedKB).toLocaleString() + ' KB / ' + Math.round(totalKB).toLocaleString() + ' KB';
            document.getElementById('eta-speed').innerText = speedKBps.toFixed(1) + ' KB/s';
            document.getElementById('eta-time').innerText = timeStr;
        }

        // YEDEK ALMA İŞLEMİ (Onay kutusu yok)
        document.getElementById('btn-start-backup').addEventListener('click', function() {
            const btn = this;
            btn.disabled = true;
            appendLog('Yedek alma işlemi başlatıldı...', 'info');
            startTime = Date.now();

            fetch('?action=get_tables', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN)
            })
            .then(res => res.json())
            .then(res => {
                if (!res.success) throw new Error(res.message);
                
                const tables = res.data.tables;
                const tmpFile = res.data.tmp_file;
                const totalDbBytes = res.data.db_raw_bytes || 1;
                let currentTableIndex = 0;

                function backupNextTable() {
                    if (currentTableIndex >= tables.length) {
                        // Yedeklemeyi Tamamla
                        fetch('?action=finalize_backup', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                            body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN) + '&tmp_file=' + encodeURIComponent(tmpFile)
                        })
                        .then(r => r.json())
                        .then(finRes => {
                            btn.disabled = false;
                            if (finRes.success) {
                                appendLog(finRes.message, 'info');
                                updateProgressUI(totalDbBytes, totalDbBytes);
                                addBackupToTable(finRes.data.new_backup);
                            } else {
                                appendLog('Yedek tamamlama hatası: ' + finRes.message, 'error');
                            }
                        });
                        return;
                    }

                    const tableName = tables[currentTableIndex];
                    document.getElementById('p-status').innerText = 'Yedekleniyor: ' + tableName;

                    fetch('?action=backup_table', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                        body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN) + '&table=' + encodeURIComponent(tableName) + '&tmp_file=' + encodeURIComponent(tmpFile)
                    })
                    .then(r => r.json())
                    .then(tblRes => {
                        if (!tblRes.success) throw new Error(tblRes.message);
                        
                        currentTableIndex++;
                        const approxWritten = Math.round((currentTableIndex / tables.length) * totalDbBytes);
                        updateProgressUI(approxWritten, totalDbBytes);
                        backupNextTable();
                    })
                    .catch(err => {
                        btn.disabled = false;
                        appendLog('Tablo yedekleme hatası (' + tableName + '): ' + err.message, 'error');
                    });
                }

                backupNextTable();
            })
            .catch(err => {
                btn.disabled = false;
                appendLog('Yedekleme başlatılamadı: ' + err.message, 'error');
            });
        });

        // YEDEKTEN GERİ YÜKLEME İŞLEMİ (Onay kutusu yok)
        document.getElementById('backup-table-body').addEventListener('click', function(e) {
            if (e.target.classList.contains('btn-restore')) {
                const fileName = e.target.getAttribute('data-file');
                appendLog('Geri yükleme başlatılıyor: ' + fileName, 'warn');
                startTime = Date.now();

                fetch('?action=prepare_restore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                    body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN) + '&file=' + encodeURIComponent(fileName)
                })
                .then(r => r.json())
                .then(res => {
                    if (!res.success) throw new Error(res.message);

                    const totalBytes = res.data.total_bytes;
                    let currentOffset = res.data.resumed_offset || 0;
                    let procTables = res.data.resumed_tables || 0;
                    let procRows = res.data.resumed_rows || 0;

                    function executeChunk() {
                        document.getElementById('p-status').innerText = 'Geri Yükleniyor...';
                        fetch('?action=execute_chunks', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                            body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN) + 
                                  '&file=' + encodeURIComponent(fileName) + 
                                  '&offset=' + currentOffset + 
                                  '&processed_tables=' + procTables + 
                                  '&processed_rows=' + procRows
                        })
                        .then(r => r.json())
                        .then(chkRes => {
                            if (!chkRes.success) throw new Error(chkRes.message);

                            currentOffset = chkRes.data.new_offset;
                            procTables = chkRes.data.processed_tables;
                            procRows = chkRes.data.processed_rows;

                            updateProgressUI(currentOffset, totalBytes);

                            if (chkRes.data.completed) {
                                appendLog('Geri yükleme başarıyla tamamlandı! Toplam İşlenen Satır: ' + procRows, 'info');
                                fetchLiveMetrics();
                            } else {
                                executeChunk();
                            }
                        })
                        .catch(err => {
                            appendLog('Geri yükleme sırasında hata oluştu: ' + err.message, 'error');
                        });
                    }

                    executeChunk();
                })
                .catch(err => {
                    appendLog('Geri yükleme hazırlığı başarısız: ' + err.message, 'error');
                });
            }

            // TEK DOSYA SİLME (Onay kutusu yok)
            if (e.target.classList.contains('btn-delete')) {
                const btn = e.target;
                const fileName = btn.getAttribute('data-file');

                fetch('?action=delete_selected', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                    body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN) + '&file=' + encodeURIComponent(fileName)
                })
                .then(r => r.json())
                .then(res => {
                    if (res.success) {
                        appendLog('Yedek silindi: ' + fileName, 'info');
                        const tr = btn.closest('tr');
                        tr.remove();
                        updateBatchButton();
                    } else {
                        appendLog('Silme hatası: ' + res.message, 'error');
                    }
                });
            }
        });

        // TOPLU SİLME İŞLEMİ (Onay kutusu yok)
        batchBtn.addEventListener('click', function() {
            const checkedBoxes = document.querySelectorAll('.backup-select:checked');
            const files = Array.from(checkedBoxes).map(cb => cb.value);

            if (files.length === 0) return;

            let bodyParams = 'csrf_token=' + encodeURIComponent(CSRF_TOKEN);
            files.forEach(f => { bodyParams += '&files[]=' + encodeURIComponent(f); });

            fetch('?action=delete_batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                body: bodyParams
            })
            .then(r => r.json())
            .then(res => {
                if (res.success) {
                    appendLog(res.message, 'info');
                    checkedBoxes.forEach(cb => cb.closest('tr').remove());
                    selectAll.checked = false;
                    updateBatchButton();
                } else {
                    appendLog('Toplu silme hatası: ' + res.message, 'error');
                }
            });
        });

        // VERİTABANINI SIFIRLAMA İŞLEMİ (Onay kutusu yok)
        document.getElementById('btn-clear-db').addEventListener('click', function() {
            const btn = this;
            btn.disabled = true;
            appendLog('Veritabanı sıfırlanıyor (Tüm tablolar ve yapılardan temizleniyor)...', 'warn');

            fetch('?action=clear_db', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': CSRF_TOKEN },
                body: 'csrf_token=' + encodeURIComponent(CSRF_TOKEN)
            })
            .then(r => r.json())
            .then(res => {
                btn.disabled = false;
                if (res.success) {
                    appendLog('Veritabanı başarıyla temizlendi ve sıfırlandı.', 'info');
                    fetchLiveMetrics();
                } else {
                    appendLog('Temizleme hatası: ' + res.message, 'error');
                }
            })
            .catch(err => {
                btn.disabled = false;
                appendLog('Sıfırlama hatası: ' + err.message, 'error');
            });
        });

        // Tabloya Dinamik Yeni Yedek Ekleme (Sayfa Yenilenmeden)
        function addBackupToTable(b) {
            const tbody = document.getElementById('backup-table-body');
            const noRow = document.getElementById('no-backup-row');
            if (noRow) noRow.remove();

            const tr = document.createElement('tr');
            tr.setAttribute('data-file', b.name);
            tr.innerHTML = `
                <td class="checkbox-cell"><input type="checkbox" class="backup-select" value="${b.name}"></td>
                <td><strong>${b.name}</strong></td>
                <td>${b.size}</td>
                <td>${b.date}</td>
                <td><span class="badge badge-success">Doğrulandı</span></td>
                <td>
                    <div class="action-btns">
                        <button class="btn btn-blue btn-sm btn-restore" data-file="${b.name}">Geri Yükle</button>
                        <form method="POST" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="${CSRF_TOKEN}">
                            <input type="hidden" name="action" value="download_backup">
                            <input type="hidden" name="file" value="${b.name}">
                            <button type="submit" class="btn btn-green btn-sm">İndir</button>
                        </form>
                        <button class="btn btn-red btn-sm btn-delete" data-file="${b.name}">Sil</button>
                    </div>
                </td>
            `;
            tbody.insertBefore(tr, tbody.firstChild);
        }
    </script>
</body>
</html>
