<?php

/*
======================================================================
BU SÜRÜMÜ KULLANMADAN ÖNCE
======================================================================
Bu dosya hem çalışan uygulama hem de açıklamalı kaynak olarak hazırlanmıştır.

Kontrol edilen temel noktalar:
- PHP sözdizimi kontrolü yapılmıştır.
- Yedek klasörü: /mysqlyedek
- Cron token sabit bırakılmıştır.
- HTTP ve HTTPS çalışma mantığı korunmuştur.
- Login, session ve CSRF kontrolleri korunmuştur.
- CLI işçi süreç uzun işlemler için tercih edilen yöntemdir.
- WEB işçi süreç, CLI kullanılamayan ortamlarda alternatif yöntemdir.
- Yedek dosyalarının geçici dosyadan gerçek dosyaya alınması korunmuştur.
- SHA-256 doğrulama ve geri yükleme güvenlik kontrolleri korunmuştur.

ÖNEMLİ:
Bu dosya gerçek sunucuda kullanılmadan önce kendi MySQL sürümünüz,
PHP sürümünüz ve hosting ortamınız üzerinde bir deneme veritabanıyla
yedekleme + geri yükleme testi yapılmalıdır.

======================================================================
*/


/*
======================================================================
PROGRAMIN GENEL MİMARİSİ
======================================================================

Bu dosya tek bir PHP dosyası içinde çalışan bir MySQL yedekleme
uygulamasıdır. inceleme amacıyla okunurken programı şu katmanlara
ayırarak düşünmek faydalıdır:

1) AYARLAR
 Veritabanı, yönetici hesabı, yedek sayısı ve çalışma seçenekleri
 gibi sabit/ayar bilgileri burada tutulur.

2) PHP / SUNUCU TARAFI
 PHP; MySQL'e bağlanır, yedek oluşturur, yedek geri yükler,
 dosya işlemlerini yapar, kullanıcı oturumunu ve güvenliği yönetir.

3) API / İSTEK YÖNETİMİ
 Tarayıcıdan gelen action parametreleri hangi işlemin yapılacağını
 belirler. PHP işlemi yaptıktan sonra çoğu durumda JSON cevap döner.

4) MYSQL / VERİTABANI
 PDO üzerinden MySQL ile haberleşilir. SQL sorguları burada çalışır.

5) HTML
 Kullanıcının tarayıcıda gördüğü sayfanın yapısını oluşturur.

6) CSS
 HTML'in görünümünü ve yerleşimini düzenler.

7) JAVASCRIPT
 Butonlara ve formlara tepki verir, PHP API'sine istek gönderir,
 gelen sonucu ekrana aktarır ve gerektiğinde ilerleme bilgisini
 tekrar sorgular.

 EN ÖNEMLİ NOKTA:
Bir butona basıldığında bütün işlem tarayıcıda gerçekleşmez.
Genellikle akış şöyledir:

Kullanıcı → JavaScript → HTTP isteği → PHP → MySQL/Dosya sistemi
 ← JSON/HTML cevap ← PHP ← işlem sonucu

Bu dosyayı öğrenirken fonksiyonların sadece "ne yaptığını" değil,
"NEDEN ayrı bir fonksiyon olarak yazıldığını" da inceleyin.

======================================================================
*/

/**
 * ==============================================================================
 * VEDO MYSQL YEDEKLEME VE SUNUCU İZLEME PANELİ
 * ==============================================================================
 * Destek: PHP 8.0+ | MySQL 5.7+ / 8.0+ / MariaDB
 * Amaç: Güvenli yedek alma, kontrol edilmiş geri yükleme, nesne aktarımı ve sunucu izlemesi.
 * Çalışma modeli: Kısa HTTP istekleri, durum dosyaları ve gerektiğinde arka plan CLI işlemi.
 * Güvenlik: Oturum, CSRF, dosya yolu, SQL ayrıştırma ve ortak işlem kilitleri korunur.
 * Optimizasyon ilkesi: Çalışan yedek/geri yükleme algoritması korunur; yalnızca kanıtlanmış tekrarlar ve gereksiz arayüz/okuma/yazma maliyetleri azaltılır.
 * ==============================================================================
 */

declare(strict_types=1);

// PHP çalışma tipini bir kez belirleriz. Aynı bilgiyi tekrar okumayız.
define('VEDO_IS_CLI', PHP_SAPI === 'cli');

// =============================================================================
// PANEL VE VERİ TABANI AYARLARI
// Burada sistemin temel ayarları bulunur.
// Sunucuya göre değişecek ayarlar burada bulunur.
// =============================================================================

$config = [
 // MySQL sunucusunun adresi.
 // Genellikle aynı sunucudaysa: localhost
 'db_host' => getenv('VEDO_DB_HOST') ?: 'localhost',

 // MySQL'e bağlanmak için kullanılacak kullanıcı adı.
 'db_user' => getenv('VEDO_DB_USER') ?: '???????????',

 // MySQL kullanıcısının şifresi.
 'db_pass' => getenv('VEDO_DB_PASSWORD') ?: '???????????',

 // Yedek alırken ve geri yüklerken kullanılacak veri tabanının adı.
 'db_name' => getenv('VEDO_DB_NAME') ?: '???????????',

 // Panele giriş yaparken kullanılacak yönetici kullanıcı adı.
 'auth_user' => getenv('VEDO_ADMIN_USER') ?: 'admin',

 // Panele giriş yaparken kullanılacak yönetici şifresi.
 'auth_pass' => getenv('VEDO_ADMIN_PASSWORD') ?: '???????????',

 // Sunucuda en fazla kaç tane .sql.gz yedek tutulacağını ayarlar.
 // Bu sayıya ulaşılırsa eski yedekler otomatik silinir.
 'max_backups' => 720,

 // Zamanlanmış yedek işini başlatan gizli güvenlik anahtarıdır.
 // Var olan zamanlanmış görevin bozulmaması için bu değeri değiştirmeyin.
 'cron_token' => getenv('VEDO_CRON_TOKEN') ?: 'sql_backup_a9a495811',


 // PHP’nin veri tabanı bağlantısının yeniden kullanılıp kullanılmayacağını ayarlar.
 // false = Her işlem için normal bağlantı kullanılır.
 // true = Uygun sunucularda bağlantı tekrar kullanılabilir.
 'use_persistent_pdo' => false,

 // Aynı kullanıcı hesabı için izin verilen başarısız giriş sayısı.
 'max_login_attempts' => 5,

 // Aynı IP adresinden izin verilen başarısız giriş sayısı.
 'max_ip_attempts' => 20,

 // Bir kullanıcı hesabı için toplam başarısız giriş sınırı.
 'max_user_attempts' => 10,

 // Başarısız giriş sayacının sıfırlanması için beklenecek süre.
 // Değer saniye cinsindendir. 900 = 15 dakika.
 'rate_limit_window' => 900,

 // Güvenlik nedeniyle kilitlenen hesabın tekrar kullanılabilmesi için
 // beklenecek süre. Değer saniye cinsindendir. 900 = 15 dakika.
 'lockout_time' => 900,

 // Yedek alma ve geri yükleme sırasında ortak kullanılan işlem kilidinin bekleme süresi.
 // Değer saniye cinsindendir.
 'lock_timeout' => 60,

 // Log 5 MB'ı geçtiğinde kaç eski döndürülmüş dosyanın saklanacağını ayarlar.
 'log_rotate_count' => 5,

 // Panelde kullanılacak yazı tipi.
 'ui_font' => 'Tahoma, Arial, sans-serif',

 // Panel açılışında kullanılacak varsayılan tema. Kullanıcı seçimi tarayıcıda ayrıca saklanır.
 // light = Açık tema
 // dark = Koyu tema
 'ui_default_theme' => 'dark',

 // Geri yükleme bitince veri tabanının sağlamlığı kontrol edilsin mi?
 // true = Kontrol et
 // false = Kontrol etme
 'verify_after_restore' => true,

 // Geri yükleme bitince ANALYZE TABLE çalıştırılsın mı?
 // true = Çalıştır
 // false = Çalıştırma
 'analyze_after_restore' => true,

 // Yedek alırken MyISAM tablolarında REPAIR TABLE çalıştırılsın mı, onu ayarlar.
 // Varsayılan olarak false’tur. Yedek alma sırasında yalnızca okuma yapılır.
 'repair_myisam_before_backup' => false
];

if (version_compare(PHP_VERSION, '8.0.0', '<')) {
 if (VEDO_IS_CLI) {
 fwrite(STDERR, "ERROR: Minimum PHP 8.0.0 gereklidir. Mevcut: " . PHP_VERSION . "\n");
 exit(1);
 }
 http_response_code(500);
 echo "Bu sistem minimum PHP 8.0.0 sürümünü gerektirmektedir. Mevcut sürüm: " . PHP_VERSION;
 exit;
}

// WEB ve CLI ayrı çalışır. CLI sadece
// kullanıcı CLI modunu seçtiğinde başlatılan yedek alma / geri yükleme / kontrol
// işlerinde kullanılır. WEB restore kendi web akışıyla devam eder.
$required_extensions = VEDO_IS_CLI
 ? ['pdo', 'pdo_mysql', 'json', 'zlib', 'hash']
 : ['pdo', 'pdo_mysql', 'json', 'zlib', 'session', 'hash'];
foreach ($required_extensions as $ext) {
 if (!extension_loaded($ext)) {
 if (VEDO_IS_CLI) {
 fwrite(STDERR, "ERROR: PHP uzantısı eksik: {$ext}\n");
 exit(1);
 }
 die("PHP uzantısı eksik: {$ext}");
 }
}

// Bazı hostinglerde mbstring olmayabilir.
// Bu yüzden güvenli UTF-8 yardımcıları da vardır.
function vedo_utf8_valid(string $value)
: bool {
 return preg_match('//u', $value) === 1;
}
function vedo_utf8_lower(string $value)
: string {
 return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
}
function vedo_utf8_substr(string $value, int $start, ?int $length = null)
: string {
 if (function_exists('mb_substr')) {
 return mb_substr($value, $start, $length, 'UTF-8');
 }
 if (!vedo_utf8_valid($value)) {
 return substr($value, $start, $length);
 }
 $chars = preg_split('//u', $value, -1, PREG_SPLIT_NO_EMPTY);
 if ($chars === false) {
 return substr($value, $start, $length);
 }
 return implode('', $length === null ? array_slice($chars, $start) : array_slice($chars, $start, $length));
}
function vedo_utf8_strlen(string $value)
: int {
 if (function_exists('mb_strlen')) {
 return mb_strlen($value, 'UTF-8');
 }
 if (!vedo_utf8_valid($value)) {
 return strlen($value);
 }
 $count = preg_match_all('/./us', $value, $matches);
 return $count === false ? strlen($value) : $count;
}

// Programda ortak kullanılan sabit ayarlar.
define('VEDO_BACKUP_FORMAT', '2');
define('VEDO_QUERY_BUFFER_MAX', 52428800); // 50 MB
define('VEDO_CHUNK_ROW_LARGE', 5000);
define('VEDO_CHUNK_ROW_MEDIUM', 2500);
define('VEDO_CHUNK_ROW_SMALL', 1500);
define('VEDO_CHUNK_ROW_DEFAULT', 800);
define('VEDO_MAX_LOG_SIZE', 5242880); // 5 MB
define('VEDO_DATABASE_OPERATION_LOCK', 'database_operation'); // Yedek alma ve geri yükleme için ortak kilit
define('VEDO_WEB_RESTORE_STALE_RECOVERY_SECONDS', 120); // WEB restore sırasında kurtarma için bekleme süresi
define('VEDO_WEB_RESTORE_PREP_SLICE_SECONDS', 5.5); // Tek WEB isteğinde yapılan hazırlık parçası. Amaç zaman aşımını önlemektir.
define('VEDO_WEB_RESTORE_PREP_SLICE_BYTES', 32 * 1024 * 1024); // Her hazırlık parçası en fazla 32 MB olur. Böylece dosya daha az taranır.
define('VEDO_WEB_RESTORE_PREP_SLICE_MIN_BYTES', 8 * 1024 * 1024);
define('VEDO_WEB_RESTORE_PREP_SLICE_MAX_BYTES', 32 * 1024 * 1024);
define('VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS', 1800); // Yarıda kalan hazırlık işi en fazla 30 dakika devam ettirilebilir.
define('VEDO_LOG_ROTATION_CHECK_SECONDS', 5); // Log boyutu en fazla 5 saniyede bir kontrol edilir.
define('VEDO_FINISHED_JOB_STATE_TTL_SECONDS', 120); // Biten işlerin durum dosyası 2 dakika sonra silinir.
define('VEDO_LOG_STREAM_INITIAL_LINES', 500); // SSE ilk bağlantıda yalnızca son log satırlarını taşır.
define('VEDO_DASHBOARD_LOG_LINES', 300); // Dashboard JSON yanıtında yalnızca son log satırları bulunur.
define('VEDO_CLIENT_LOG_MAX_LINES', 2000); // Tarayıcı tarafında canlı log tamponunun üst sınırı.
define('VEDO_LIVE_METRICS_SAMPLE_MS', 100); // CPU ölçümünde bekleme süresi.
define('VEDO_LIVE_METRICS_INTERVAL_MS', 1000); // CPU/RAM/DISK bilgileri 1 saniyede bir yenilenir.

/**
 * Biriktirilmiş ekran çıktısını temizler.
 */



// =============================================================================
// PHP - ÇALIŞMA ORTAMINI HAZIRLAMA
// Bu bölüm PHP'nin temel çalışma ortamını hazırlar.
// Örneğin çıktı tamponunu temizler, hataların kullanıcıya doğrudan basılmasını
// önler ve dosya/oturum işlemlerinin daha kontrollü yapılmasını sağlar.
// =============================================================================

function clear_buffers()
: void {
 if (headers_sent()) return;
 while (ob_get_level() > 0) {
 ob_end_clean();
 }
}

clear_buffers();
if (!headers_sent() && ob_get_level() === 0) {
 ob_start();
}
if (!VEDO_IS_CLI) {
 @ini_set('display_errors', '0');
 @ini_set('display_startup_errors', '0');
}

/**
 * Dosyayı birkaç kez yazmayı dener. Yine olmazsa hatayı loga yazar ve başarısız olduğunu bildirir.
 */
function safe_file_put_contents(string $filepath, string $data, int $flags = 0)
: bool {
 $attempts = 0;
 $max_attempts = 3;
 $useAppend = (($flags & FILE_APPEND) === FILE_APPEND);
 $needLock = (($flags & LOCK_EX) === LOCK_EX);

 while ($attempts < $max_attempts) {
 $attempts++;
 $mode = $useAppend ? 'ab' : ($needLock ? 'c+b' : 'wb');
 $fp = @fopen($filepath, $mode);
 if ($fp !== false) {
 $ok = true;
 $originalEnd = 0;
 $offset = 0;
 $length = strlen($data);

 if ($needLock) {
 $ok = @flock($fp, LOCK_EX);
 }

 if ($ok) {
 if (!$useAppend && $needLock) {
 $ok = @ftruncate($fp, 0) && @rewind($fp);
 } elseif ($useAppend) {
 $stat = @fstat($fp);
 $originalEnd = is_array($stat) ? (int)($stat['size'] ?? 0) : 0;
 if (@fseek($fp, 0, SEEK_END) !== 0) $ok = false;
 }

 if ($ok && $offset < $length) {
 $written = @fwrite($fp, $data);
 if ($written === false || $written === 0) {
 $ok = false;
 } else {
 $offset = $written;
 }
 }
 while ($ok && $offset < $length) {
 $written = @fwrite($fp, substr($data, $offset));
 if ($written === false || $written === 0) {
 $ok = false;
 break;
 }
 $offset += $written;
 }
 if ($ok && !@fflush($fp)) $ok = false;

 if (!$ok && $useAppend && $originalEnd >= 0) {
 @fflush($fp);
 @ftruncate($fp, $originalEnd);
 @fseek($fp, 0, SEEK_END);
 }
 }

 if ($needLock) @flock($fp, LOCK_UN);
 @fclose($fp);
 if ($ok && $offset === $length) return true;
 }
 usleep(50000);
 }

 $lastError = error_get_last();
 $errMsg = $lastError['message'] ?? 'Bilinmeyen Disk I/O Hatası';
 static $failureReporting = false;
 if (class_exists('Logger') && !$failureReporting) {
 $failureReporting = true;
 try {
 Logger::error("Dosya yazma başarısız [{$filepath}] ({$attempts} deneme): {$errMsg}");
 } catch (Throwable $logError) {
 error_log("VEDO_FILE_WRITE_FAILURE: {$filepath} | {$errMsg}");
 } finally {
 $failureReporting = false;
 }
 } else {
 error_log("VEDO_FILE_WRITE_FAILURE: {$filepath} | {$errMsg}");
 }
 return false;
}

// =============================================================================
// PHP - LOG SİSTEMİ
// Programın yaptığı önemli işlemleri, uyarıları ve hataları sistem.log dosyasına
// yazar. Böylece ekranda görünmeyen bir sorunun nedenini sonradan inceleyebiliriz.
// =============================================================================

class Logger {
 private static string $logFile = '';
 private static string $logDir = '';
 private static bool $available = false;
 private static int $maxRotateFiles = 5;
 private static int $lastRotationCheck = 0;

 public static function init(string $dir, int $rotateCount = 5): void {
 self::$logDir = $dir;
 self::$logFile = $dir . '/system.log';
 self::$available = is_dir($dir) && is_writable($dir);
 self::$maxRotateFiles = max(1, $rotateCount);
 self::$lastRotationCheck = 0;
 }

 /**
 * Log mesajındaki gizli bilgileri saklar ve çok uzun mesajları kısaltır.
 */
 private static function sanitize(string $message): string {
 // Bu kurallar sabit tutulur. Yoğun işlerde her log çağrısında
 // aynı listeyi yeniden oluşturmayız.
 static $patterns = [
 '/((?:password|passwd|pass|token|secret|csrf|session[_-]?id|authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie)\s*[:=]\s*)(?:"[^"]*"|\'[^\']*\'|[^\s,;&|}]+)/iu',
 '/("(?:password|passwd|pass|token|secret|csrf|session[_-]?id|authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie)"\s*:\s*)"[^"]*"/iu'
 ];
 $message = preg_replace($patterns[0], '$1***REDACTED***', $message) ?? $message;
 $message = preg_replace($patterns[1], '$1"***REDACTED***"', $message) ?? $message;
 $message = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $message) ?? $message;
 $message = trim(preg_replace('/\s{2,}/u', ' ', $message) ?? $message);
 if (vedo_utf8_strlen($message) > 8000) {
 $message = vedo_utf8_substr($message, 0, 8000) . '…';
 }
 return $message;
 }

 public static function log(string $level, string $message): void {
 if (self::$logFile === '') return;
 $message = self::sanitize($message);

 // Her log satırında dosya boyutunu kontrol etmeyiz. Aralıklı kontrol ederiz.
 $now = time();
 if (self::$available && ($now - self::$lastRotationCheck) >= VEDO_LOG_ROTATION_CHECK_SECONDS) {
 self::$lastRotationCheck = $now;
 clearstatcache(true, self::$logFile);
 if (is_file(self::$logFile) && filesize(self::$logFile) > VEDO_MAX_LOG_SIZE) {
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
 public static function success(string $msg): void { self::log('SUCCESS', $msg); }
}


// =============================================================================
// PHP - HTTP / HTTPS TESPİTİ
// Bu fonksiyon isteğin HTTP mi HTTPS mi olduğunu anlamaya çalışır.
// HTTPS kullanılıyorsa güvenli oturum çerezleri ve HSTS gibi ayarlar buna göre açılır.
// =============================================================================

/*
 * ADIM ADIM: HTTPS KONTROLÜ
 * 1) Sunucunun HTTPS bilgisini kontrol eder.
 * 2) Ters proxy kullanılıyorsa X-Forwarded-Proto bilgisini de dikkate alır.
 * 3) Sonucu true/false olarak döndürür.
 * Neden? Cookie'nin secure özelliği ve güvenlik başlıkları HTTP/HTTPS
 * durumuna göre doğru ayarlanabilsin diye.
 */
function is_request_https()
: bool {
 if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
 return true;
 }

 $forwardedProto = strtolower(trim((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')));
 return $forwardedProto === 'https';
}

$nonce = base64_encode(random_bytes(16));

if (!VEDO_IS_CLI) {
 header("X-Frame-Options: DENY");
 header("X-Content-Type-Options: nosniff");
 header("Referrer-Policy: no-referrer");
 header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
 header("Pragma: no-cache");
 header("Expires: 0");
 header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';");

 header("Permissions-Policy: camera=(), microphone=(), geolocation=(), autoplay=(), fullscreen=(), payment=(), usb=(), serial=(), accelerometer=()");
 header("Cross-Origin-Opener-Policy: same-origin");
 header("Cross-Origin-Resource-Policy: same-origin");
 if (is_request_https()) {
 header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
 }
}

$backup_dir = __DIR__ . '/mysqlyedek';

if (!is_dir($backup_dir)) {
 if (!mkdir($backup_dir, 0755, true) && !is_dir($backup_dir)) {
 if (VEDO_IS_CLI) {
 fwrite(STDERR, "ERROR: Yedekleme klasoru olusturulamadi: {$backup_dir}\n");
 exit(1);
 }
 http_response_code(500);
 die("Kritik Hata: Yedekleme klasörü (" . htmlspecialchars($backup_dir) . ") oluşturulamadı!");
 }
}

Logger::init($backup_dir, (int)$config['log_rotate_count']);

/**
 * Beklenmeyen bir PHP hatası olursa burada yakalanır. Kullanıcıya ham hata metni gösterilmez.
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
 safe_file_put_contents($htaccess_path, "<IfModule mod_authz_core.c>\n Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n Order deny,allow\n Deny from all\n</IfModule>\n");
}

$index_path = $backup_dir . '/index.html';
if (!file_exists($index_path)) {
 safe_file_put_contents($index_path, '');
}

if (!is_writable($backup_dir)) {
 if (VEDO_IS_CLI) {
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

/**
 * Yedek dosya adını doğrular.
 *
 * Dosya adı yalnızca mevcut yedek dosyasının adı olmalıdır; dizin ayırıcıları,
 * NUL ve kontrol karakterleri kabul edilmez. Eski/elle yüklenmiş geçerli
 * yedeklerin boşluk, parantez veya Türkçe karakter içermesi geri yükleme işlemini
 * gereksiz yere engellememesi için ASCII ile sınırlama yapılmaz.
 */

// =============================================================================
// PHP - YEDEK DOSYASI VE DOSYA YOLU GÜVENLİĞİ
// Bu bölüm yedek dosyalarının adını ve erişilecek yolları kontrol eder.
// Amaç: Kullanıcının ../ gibi yollarla panel dışındaki dosyalara ulaşmasını engellemektir.
// =============================================================================

function validate_backup_filename(string $filename)
: bool {
 if ($filename === '' || strlen($filename) > 255) {
 return false;
 }
 if (str_contains($filename, "\0") || str_contains($filename, '/') || str_contains($filename, '\\')) {
 return false;
 }
 if (preg_match('/[\x00-\x1F\x7F]/', $filename)) {
 return false;
 }
 if (!str_ends_with($filename, '.sql.gz')) {
 return false;
 }
 return basename($filename) === $filename;
}

function is_emergency_backup_filename(string $filename)
: bool {
 return str_starts_with($filename, '.vedo_emergency_') && str_ends_with($filename, '.sql.gz');
}

function cleanup_emergency_backup_artifacts(string $backup_dir, string $file)
: void {
 if ($file === '' || !validate_backup_filename($file) || !is_emergency_backup_filename($file)) {
 return;
 }

 try {
 $safe = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
 if (is_file($safe)) @unlink($safe);
 if (is_file($safe . '.sha256')) @unlink($safe . '.sha256');
 if (is_file($safe . '.meta.json')) @unlink($safe . '.meta.json');
 Logger::info('Emergency backup temizlendi: ' . $file);
 } catch (Throwable $e) {
 Logger::warning('Emergency backup temizlenirken hata [' . $file . ']: ' . $e->getMessage());
 }
}
/**
 * Dosya yolunun izin verilen klasörün içinde olduğunu kontrol eder. Güvensiz yolları engeller.
 */
function validate_path_safe(string $filePath, string $baseDir)
: string {
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
/**
 * RESTORE BAKIM DURUMU
 *
 * WEB geri yükleme birden fazla HTTP isteğine yayıldığı için flock() iki durumu tekrar sorma isteği
 * iki WEB isteği arasında kilit bırakılabilir. Bu dosya restore devam ederken diğer DB işlemlerini durdurur.
 * Harici programların MySQL'e yazmasını tek başına durdurmaz, sadece panelde durum işareti olarak kullanılır.
 */
function restore_maintenance_marker_path(string $backup_dir)
: string {
 return $backup_dir . '/.vedo_restore_maintenance.json';
}

function read_restore_maintenance(string $backup_dir)
: array {
 $path = restore_maintenance_marker_path($backup_dir);
 if (!is_file($path)) return [];

 $raw = @file_get_contents($path);
 if (!is_string($raw) || trim($raw) === '') {
 return ['_invalid' => true, 'status' => 'invalid_marker'];
 }

 try {
 $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
 } catch (Throwable $e) {
 Logger::error('Restore bakım marker okunamadı veya bozuk: ' . $e->getMessage());
 return ['_invalid' => true, 'status' => 'invalid_marker'];
 }

 if (!is_array($data)) {
 return ['_invalid' => true, 'status' => 'invalid_marker'];
 }

 $jobId = (string)($data['job_id'] ?? '');
 $engine = (string)($data['engine'] ?? '');
 $status = (string)($data['status'] ?? '');
 $startedAt = (int)($data['started_at'] ?? 0);

 if (!preg_match('/^[a-f0-9]{32}$/', $jobId)
 || !in_array($engine, ['web', 'cli'], true)
 || !in_array($status, ['active', 'completed', 'failed'], true)
 || $startedAt <= 0) {
 Logger::error('Restore bakım marker yapısı geçersiz; güvenli tarafta kalmak için işlemler engellenecek.');
 return ['_invalid' => true, 'status' => 'invalid_marker'];
 }

 return $data;
}

function find_active_restore_job_for_maintenance(string $backup_dir, string $ignore_job_id = '')
: array {
 $files = glob($backup_dir . '/.cli_job_*.json') ?: [];
 $now = time();

 foreach ($files as $path) {
 if (!is_file($path)) continue;
 $base = basename($path);
 if (!preg_match('/^\.cli_job_([a-f0-9]{32})\.json$/', $base, $m)) continue;
 $jobId = $m[1];
 if ($ignore_job_id !== '' && hash_equals($ignore_job_id, $jobId)) continue;

 $raw = @file_get_contents($path);
 $data = is_string($raw) ? json_decode($raw, true) : null;
 if (!is_array($data)) {
 Logger::error('Restore job state okunamadı/bozuk; fail-closed uygulanıyor: ' . $path);
 return ['_invalid' => true, 'status' => 'invalid_job_state', 'path' => $path, 'job_id' => $jobId];
 }
 if (($data['type'] ?? '') !== 'restore') continue;

 // Kurtarma gereken restore, son durumu FAILED olsa bile güvenli
 // olarak aktif sayılır. Durum dosyası kaybolsa bile yeni işlemlerin
 // başlamasına izin verilmez.
 if (!empty($data['recovery_required'])) {
 $data['job_id'] = $jobId;
 $data['_recovery_required'] = true;
 return $data;
 }

 if (!in_array((string)($data['status'] ?? ''), ['starting', 'verifying', 'waiting', 'running', 'clearing', 'restoring'], true)) continue;

 $updatedAt = max(0, (int)($data['updated_at'] ?? 0), (int)@filemtime($path));
 $age = $updatedAt > 0 ? max(0, $now - $updatedAt) : PHP_INT_MAX;
 $webPrepareState = ($data['engine'] ?? '') === 'web'
 && ($data['type'] ?? '') === 'restore'
 && ($data['phase'] ?? '') === 'prepare_stream';
 $recoverableWebRestore = is_recoverable_web_restore_state($data);
 $longRunningWebProcess = ($data['engine'] ?? '') === 'web'
 && ($data['type'] ?? '') === 'restore'
 && in_array((string)($data['phase'] ?? ''), ['emergency_backup', 'prepare_stream', 'analyze'], true);
 $ttl = match ((string)($data['status'] ?? '')) {
 'starting' => $webPrepareState ? 300 : 300,
 'waiting' => $webPrepareState ? VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS : (($recoverableWebRestore || $longRunningWebProcess) ? PHP_INT_MAX : 900),
 default => $webPrepareState ? VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS : (($recoverableWebRestore || $longRunningWebProcess) ? PHP_INT_MAX : 7200),
 };
 if ($age >= $ttl) continue;

 $data['job_id'] = $jobId;
 return $data;
 }

 return [];
}

function restore_maintenance_is_blocking(array $state)
: bool {
 if ($state === []) return false;
 if (!empty($state['_invalid'])) return true;
 return (string)($state['status'] ?? 'active') === 'active' || !empty($state['recovery_required']);
}

function mark_restore_maintenance_recovery_required(string $backup_dir, string $job_id, string $reason)
: void {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 throw new Exception('Geçersiz restore bakım job ID.');
 }

 $path = restore_maintenance_marker_path($backup_dir);
 $current = read_restore_maintenance($backup_dir);
 if ($current !== [] && empty($current['_invalid'])) {
 $currentJob = (string)($current['job_id'] ?? '');
 if ($currentJob !== '' && !hash_equals($currentJob, $job_id)) {
 Logger::error('Restore bakım marker başka bir job tarafından tutuluyor; mevcut marker korunuyor.');
 return;
 }
 }

 $jobState = read_cli_job_state($backup_dir, $job_id);
 $engine = in_array((string)($jobState['engine'] ?? ''), ['web', 'cli'], true)
 ? (string)$jobState['engine']
 : (string)($current['engine'] ?? 'web');

 $marker = [
 'job_id' => $job_id,
 'engine' => $engine,
 'status' => 'failed',
 'recovery_required' => true,
 'started_at' => (int)($current['started_at'] ?? $jobState['job_started_at'] ?? time()),
 'failed_at' => time(),
 'pid' => getmypid() ?: 0,
 'host' => gethostname() ?: 'host',
 'error' => vedo_utf8_substr($reason, 0, 2000)
 ];

 $json = json_encode($marker, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
 $tmp = $path . '.' . $job_id . '.recovery.tmp';
 if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
 @unlink($tmp);
 throw new Exception('Restore recovery-required bakım durumu atomik olarak yazılamadı.');
 }
}

function begin_restore_maintenance(string $backup_dir, string $job_id, string $engine)
: void {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 throw new Exception('Geçersiz restore bakım job ID.');
 }
 if (!in_array($engine, ['web', 'cli'], true)) {
 throw new Exception('Geçersiz restore bakım motoru.');
 }

 $path = restore_maintenance_marker_path($backup_dir);
 $existing = read_restore_maintenance($backup_dir);
 if ($existing !== []) {
 if (!empty($existing['_invalid'])) {
 throw new Exception('Restore bakım marker dosyası bozuk. Güvenlik nedeniyle yeni veritabanı işlemi başlatılamaz; marker dosyasını kontrol edin.');
 }
 $existingJob = (string)($existing['job_id'] ?? '');
 $existingStatus = (string)($existing['status'] ?? 'active');
 if ($existingJob !== '' && $existingJob !== $job_id && ($existingStatus === 'active' || !empty($existing['recovery_required']))) {
 throw new Exception('Başka bir restore bakım işlemi veya recovery gerektiren restore aktif. Yeni restore başlatılamaz.');
 }
 if ($existingJob === $job_id && !empty($existing['recovery_required'])) {
 throw new Exception('Bu restore işi recovery gerektiriyor; yeni restore aynı job kimliğiyle başlatılamaz.');
 }
 }

 $marker = [
 'job_id' => $job_id,
 'engine' => $engine,
 'status' => 'active',
 'started_at' => time(),
 'pid' => getmypid() ?: 0,
 'host' => gethostname() ?: 'host'
 ];

 $json = json_encode($marker, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
 $tmp = $path . '.' . $job_id . '.tmp';
 if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
 @unlink($tmp);
 throw new Exception('Restore bakım durumu atomik olarak yazılamadı.');
 }
}

function end_restore_maintenance(string $backup_dir, string $job_id = '')
: void {
 $path = restore_maintenance_marker_path($backup_dir);
 if (!is_file($path)) return;

 $current = read_restore_maintenance($backup_dir);
 if (!empty($current['_invalid'])) {
 Logger::warning('Bozuk restore bakım marker otomatik silinmedi: güvenli tarafta kalınıyor.');
 return;
 }

 $currentJob = (string)($current['job_id'] ?? '');
 if ($job_id !== '' && ($currentJob === '' || $currentJob !== $job_id)) {
 return;
 }
 if (!empty($current['recovery_required'])) {
 Logger::warning('Recovery gerektiren restore bakım marker silinmedi; güvenli durum korunuyor.');
 return;
 }

 @unlink($path);
 foreach (glob($path . '.*.tmp') ?: [] as $tmp) {
 @unlink($tmp);
 }
}

function assert_restore_maintenance_allows_action(string $backup_dir, string $action)
: void {
 // Her API kontrolünden önce süresi geçmiş WEB hazırlık durumunu temizle.
 // Böylece süresi dolmuş bir iş yeni işlemleri
 // gereksiz yere kilitlemez.
 cleanup_stale_cli_job_states($backup_dir);

 $blockedActions = [
 'run_full_backup',
 'delete_backup',
 'bulk_delete_backups',
 'import_sql_upload',
 'db_table_maintenance',
 'db_table_truncate',
 'db_table_drop',
 'empty_database',
 'db_tables',
 'db_table_data',
 'db_table_structure',
 'get_dashboard_data'
 ];

 if (!in_array($action, $blockedActions, true)) return;

 $state = read_restore_maintenance($backup_dir);
 if ($state === []) {
 $activeRestore = find_active_restore_job_for_maintenance($backup_dir);
 if ($activeRestore !== []) {
 $jobId = (string)($activeRestore['job_id'] ?? '');
 throw new Exception(
 'Restore işlemi aktif görünüyor ancak bakım marker dosyası yok. Güvenlik nedeniyle veritabanı işlemi/okuması durduruldu.' .
 ($jobId !== '' ? ' Restore Job: ' . $jobId : '')
 );
 }
 return;
 }

 if (!empty($state['_invalid'])) {
 throw new Exception('Restore bakım durumu doğrulanamadı. Güvenlik nedeniyle veritabanı işlemi/okuması durduruldu.');
 }

 if (restore_maintenance_is_blocking($state)) {
 $jobId = (string)($state['job_id'] ?? '');
 throw new Exception(
 'Restore işlemi devam ediyor veya recovery gerektiriyor. Veritabanı üzerinde yeni bir işlem başlatılamaz.' .
 ($jobId !== '' ? ' Restore Job: ' . $jobId : '')
 );
 }
}

function assert_restore_maintenance_marker_valid(string $backup_dir, string $ignore_job_id = '')
: void {
 // Normal DB işlemleri de süresi geçmiş WEB hazırlık durumunun
 // temizlendiğini görmelidir. Aksi halde süresi dolmuş bir hazırlık işi
 // yeni işlemleri gereksiz yere kilitleyebilir.
 cleanup_stale_cli_job_states($backup_dir);
 $state = read_restore_maintenance($backup_dir);
 if (!empty($state['_invalid'])) {
 throw new Exception('Restore bakım marker dosyası bozuk veya okunamıyor. Güvenlik nedeniyle veritabanı işlemi başlatılamaz.');
 }
 if ($state !== [] && !empty($state['recovery_required'])) {
 throw new Exception('Restore recovery gerektiriyor. Emergency snapshot/recovery tamamlanmadan yeni veritabanı işlemi başlatılamaz.');
 }

 $activeRestore = find_active_restore_job_for_maintenance($backup_dir, $ignore_job_id);
 if ($activeRestore !== []) {
 if (!empty($activeRestore['_invalid'])) {
 throw new Exception('Restore job durumu doğrulanamadı. Güvenlik nedeniyle yeni veritabanı işlemi başlatılamaz.');
 }
 $jobId = (string)($activeRestore['job_id'] ?? '');
 $reason = !empty($activeRestore['_recovery_required'])
 ? 'Recovery gerektiren önceki restore bulundu.'
 : 'Başka bir restore işlemi aktif.';
 throw new Exception($reason . ' Yeni veritabanı işlemi başlatılamaz.' . ($jobId !== '' ? ' Restore Job: ' . $jobId : ''));
 }

 if ($state === [] && $ignore_job_id !== '') {
 $ownJob = read_cli_job_state($backup_dir, $ignore_job_id);
 if (is_array($ownJob) && ($ownJob['type'] ?? '') === 'restore') {
 // Restore kendi durum dosyasını kaybetse bile bu çalışanı gereksiz yere durdurma.
 // fakat yeni bağımsız işleri aktif geri yükleme yardımcı'ı yukarıda bloke eder.
 return;
 }
 }
}

function require_post()
: void {
 if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
 json_response(false, 'Bu işlem için POST isteği gereklidir.', [], 405);
 }
}
function require_get()
: void {
 if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
 json_response(false, 'Bu işlem için GET isteği gereklidir.', [], 405);
 }
}

/**
 * Tüm log dosyalarını eskiden yeniye okur ve ekranda gösterir. Saklanan kayıtlar atlanmaz.
 */
function read_all_log_lines(string $logDir, int $rotateCount = 5)
: array {
 $lines = [];
 $rotateCount = max(0, $rotateCount);
 $paths = [];

 for ($i = $rotateCount; $i >= 1; $i--) {
 $paths[] = $logDir . '/system.log.' . $i;
 }
 $paths[] = $logDir . '/system.log';

 foreach ($paths as $path) {
 if (!is_file($path) || !is_readable($path)) continue;
 $fp = @fopen($path, 'rb');
 if ($fp === false) continue;
 try {
 while (($line = fgets($fp)) !== false) {
 $line = rtrim($line, "\r\n");
 if ($line !== '') $lines[] = $line;
 }
 } finally {
 @fclose($fp);
 }
 }

 return $lines;
}

/**
 * Log dosyalarının tamamını belleğe almadan yalnızca son satırları döndürür.
 * Döndürülmüş loglar eskiden yeniye işlenir; sonuç sırası kronolojiktir.
 */
function read_recent_log_lines(string $logDir, int $rotateCount = 5, int $maxLines = 500)
: array {
 $maxLines = max(1, $maxLines);
 $rotateCount = max(0, $rotateCount);
 $paths = [];

 for ($i = $rotateCount; $i >= 1; $i--) {
 $paths[] = $logDir . '/system.log.' . $i;
 }
 $paths[] = $logDir . '/system.log';

 $ring = [];
 $count = 0;
 $next = 0;

 foreach ($paths as $path) {
 if (!is_file($path) || !is_readable($path)) continue;
 $fp = @fopen($path, 'rb');
 if ($fp === false) continue;
 try {
 while (($line = fgets($fp)) !== false) {
 $line = rtrim($line, "\r\n");
 if ($line === '') continue;

 if ($count < $maxLines) {
 $ring[] = $line;
 } else {
 $ring[$next] = $line;
 }
 $count++;
 $next = $count < $maxLines ? $count : (($next + 1) % $maxLines);
 }
 } finally {
 @fclose($fp);
 }
 }

 if ($count <= $maxLines) return $ring;
 return array_merge(array_slice($ring, $next), array_slice($ring, 0, $next));
}

function release_web_session_lock()
: void {
 if (session_status() === PHP_SESSION_ACTIVE) {
 @session_write_close();
 }
}

function json_response(bool $success, string $message = '', array $data = [], int $httpCode = 200)
: void {
 clear_buffers();
 http_response_code($httpCode);
 header('Content-Type: application/json; charset=utf-8');
 $json = json_encode([
 'success' => $success,
 'message' => $message,
 'data' => $data
 ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

 if ($json === false) {
 $json = '{"success":false,"message":"JSON yanıtı oluşturulamadı.","data":[]}';
 http_response_code(500);
 }

 echo $json;
 exit;
}

// =============================================================================
// PHP - SUNUCU KAYNAKLARINI ÖLÇME VE DİNAMİK AYARLAR
// Bu bölüm CPU, RAM ve disk durumunu okuyarak yedek/geri yükleme sırasında
// kullanılacak parça boyutlarını ve işlem hızını sunucunun kapasitesine göre ayarlar.
// =============================================================================

function get_dynamic_system_load()
: int {
 static $level = null;
 static $measuredAt = 0.0;
 $now = microtime(true);
 if ($level !== null && ($now - $measuredAt) < 2.0) {
 return $level;
 }

 $cpuPressure = null;
 if (function_exists('get_cpu_metrics_accurate')) {
 try {
 $cpuMetrics = get_cpu_metrics_accurate(80);
 if (is_array($cpuMetrics) && isset($cpuMetrics['percent'])) {
 $cpuPressure = (float)$cpuMetrics['percent'];
 }
 } catch (Throwable $e) {
 $cpuPressure = null;
 }
 }

 if ($cpuPressure === null) {
 $profile = get_dynamic_resource_profile();
 $cpuPressure = (float)($profile['cpu_pressure_percent'] ?? 0);
 }

 if ($cpuPressure >= 85) $level = 1;
 elseif ($cpuPressure >= 65) $level = 3;
 elseif ($cpuPressure >= 40) $level = 5;
 else $level = 7;

 $measuredAt = $now;
 return $level;
}

/**
 * Sunucunun gerçek kaynak durumunu tek yerde hesaplar. RAM, CPU, disk ve sunucu sınırlarına bakar. Sabit kaynak limiti kullanmaz.
 */
function get_dynamic_resource_profile(?string $diskDir = null)
: array {
 static $cache = [];
 static $cacheAt = [];
 $diskDir = ($diskDir !== null && $diskDir !== '') ? $diskDir : __DIR__;
 $now = microtime(true);

 if (isset($cache[$diskDir], $cacheAt[$diskDir]) && ($now - $cacheAt[$diskDir]) < 1.0) {
 return $cache[$diskDir];
 }

 $ram = function_exists('get_accurate_ram_metrics')
 ? get_accurate_ram_metrics()
 : ['total'=>0, 'used'=>0, 'free'=>0, 'percent'=>0, 'source'=>'fallback'];

 $ramTotal = max(0, (int)($ram['total'] ?? 0));
 $ramFree = max(0, (int)($ram['free'] ?? 0));
 if ($ramTotal > 0) $ramFree = min($ramTotal, $ramFree);
 $ramUsedPercent = $ramTotal > 0 ? (($ramTotal - $ramFree) / $ramTotal) * 100.0 : 0.0;

 $capacity = function_exists('get_effective_cpu_capacity')
 ? get_effective_cpu_capacity()
 : ['cores'=>1, 'capacity_cores'=>1.0, 'online_cores'=>1, 'quota_cores'=>null, 'cpuset_cores'=>null];
 $capacityCores = max(0.01, (float)($capacity['capacity_cores'] ?? $capacity['cores'] ?? 1));
 $load1 = 0.0;
 if (function_exists('sys_getloadavg')) {
 $loads = @sys_getloadavg();
 if (is_array($loads)) $load1 = max(0.0, (float)($loads[0] ?? 0));
 }
 $cpuPressure = min(100.0, ($load1 / $capacityCores) * 100.0);

 $diskTotalRaw = @disk_total_space($diskDir);
 $diskFreeRaw = @disk_free_space($diskDir);
 $diskTotal = ($diskTotalRaw !== false && $diskTotalRaw > 0) ? (int)$diskTotalRaw : 0;
 $diskFree = ($diskFreeRaw !== false && $diskFreeRaw >= 0) ? (int)$diskFreeRaw : 0;
 if ($diskTotal > 0) $diskFree = min($diskTotal, $diskFree);
 $diskUsedPercent = $diskTotal > 0 ? (($diskTotal - $diskFree) / $diskTotal) * 100.0 : 0.0;

 $phpCurrentUsage = function_exists('memory_get_usage') ? (int)memory_get_usage(true) : 0;
 $phpLimit = function_exists('parse_ini_size_bytes') ? parse_ini_size_bytes(ini_get('memory_limit')) : 0;
 $phpHeadroom = $phpLimit > 0 ? max(0, $phpLimit - $phpCurrentUsage) : PHP_INT_MAX;

 $effectiveFree = $ramFree;
 if ($effectiveFree <= 0 && $phpHeadroom !== PHP_INT_MAX) $effectiveFree = $phpHeadroom;
 if ($phpHeadroom !== PHP_INT_MAX && $phpHeadroom > 0) {
 $effectiveFree = min($effectiveFree > 0 ? $effectiveFree : $phpHeadroom, $phpHeadroom);
 }

 // Bir işlem için kullanılacak güvenli RAM bütçesi.
 // Bu, PHP limitini değiştirmez. İşin parça boyutunu seçmek için kullanılır.
 $operationRamBudget = $effectiveFree > 0
 ? (int)max(32 * 1024 * 1024, min(384 * 1024 * 1024, $effectiveFree * 0.25))
 : 32 * 1024 * 1024;

 // Disk için güvenli boş alan payı otomatik hesaplanır.
 $diskSafety = $diskTotal > 0
 ? (int)max(128 * 1024 * 1024, min(1024 * 1024 * 1024, $diskTotal * 0.01))
 : 128 * 1024 * 1024;

 $profile = [
 'ram_total_bytes' => $ramTotal,
 'ram_free_bytes' => $ramFree,
 'ram_used_percent' => round($ramUsedPercent, 1),
 'ram_source' => (string)($ram['source'] ?? 'unknown'),
 'php_memory_usage_bytes' => $phpCurrentUsage,
 'php_memory_limit_bytes' => $phpLimit,
 'php_memory_headroom_bytes' => $phpHeadroom,
 'operation_ram_budget_bytes' => $operationRamBudget,
 'cpu_pressure_percent' => round($cpuPressure, 1),
 'cpu_capacity_cores' => $capacityCores,
 'cpu_online_cores' => (int)($capacity['online_cores'] ?? $capacity['cores'] ?? 1),
 'cpu_quota_cores' => $capacity['quota_cores'] ?? null,
 'cpu_cpuset_cores' => $capacity['cpuset_cores'] ?? null,
 'load_1min' => round($load1, 2),
 'disk_total_bytes' => $diskTotal,
 'disk_free_bytes' => $diskFree,
 'disk_used_percent' => round($diskUsedPercent, 1),
 'disk_safety_bytes' => $diskSafety,
 'timestamp' => $now,
 ];

 $cache[$diskDir] = $profile;
 $cacheAt[$diskDir] = $now;
 return $profile;
}

function get_dynamic_insert_batch_size(?string $diskDir = null)
: int {
 $p = get_dynamic_resource_profile($diskDir);
 $ram = (int)($p['operation_ram_budget_bytes'] ?? 32 * 1024 * 1024);
 $cpu = (float)($p['cpu_pressure_percent'] ?? 0);
 $batch = match (true) {
 $ram < 64 * 1024 * 1024 => 100,
 $ram < 128 * 1024 * 1024 => 200,
 $ram < 256 * 1024 * 1024 => 400,
 $ram < 384 * 1024 * 1024 => 750,
 default => 1200,
 };
 if ($cpu >= 85) $batch = (int)floor($batch * 0.50);
 elseif ($cpu >= 70) $batch = (int)floor($batch * 0.70);
 return max(75, min(2000, $batch));
}

function get_dynamic_export_buffer_bytes(?string $diskDir = null)
: int {
 $p = get_dynamic_resource_profile($diskDir);
 $ram = (int)($p['operation_ram_budget_bytes'] ?? 32 * 1024 * 1024);
 return match (true) {
 $ram < 64 * 1024 * 1024 => 512 * 1024,
 $ram < 128 * 1024 * 1024 => 1024 * 1024,
 $ram < 256 * 1024 * 1024 => 2 * 1024 * 1024,
 $ram < 384 * 1024 * 1024 => 3 * 1024 * 1024,
 default => 4 * 1024 * 1024,
 };
}

function get_dynamic_restore_chunk_bytes(?string $diskDir = null)
: int {
 $p = get_dynamic_resource_profile($diskDir);
 $ram = (int)($p['operation_ram_budget_bytes'] ?? 32 * 1024 * 1024);
 $cpu = (float)($p['cpu_pressure_percent'] ?? 0);
 $chunk = match (true) {
 $ram < 64 * 1024 * 1024 => 256 * 1024,
 $ram < 128 * 1024 * 1024 => 512 * 1024,
 $ram < 256 * 1024 * 1024 => 1024 * 1024,
 $ram < 384 * 1024 * 1024 => 2 * 1024 * 1024,
 default => 4 * 1024 * 1024,
 };
 if ($cpu >= 85) $chunk = (int)floor($chunk * 0.50);
 elseif ($cpu >= 70) $chunk = (int)floor($chunk * 0.75);
 return max(256 * 1024, min(4 * 1024 * 1024, $chunk));
}

function get_dynamic_disk_safety_bytes(string $dir)
: int {
 $p = get_dynamic_resource_profile($dir);
 return max(128 * 1024 * 1024, (int)($p['disk_safety_bytes'] ?? 128 * 1024 * 1024));
}

function get_dynamic_web_step_budget(?string $diskDir = null)
: array {
 $p = get_dynamic_resource_profile($diskDir);
 $ram = (int)($p['operation_ram_budget_bytes'] ?? 32 * 1024 * 1024);
 $cpu = (float)($p['cpu_pressure_percent'] ?? 0);
 $disk = (float)($p['disk_used_percent'] ?? 0);

 $seconds = match (true) {
 $ram < 64 * 1024 * 1024 => 1.5,
 $ram < 128 * 1024 * 1024 => 2.0,
 $ram < 256 * 1024 * 1024 => 2.5,
 default => 4.0,
 };
 if ($cpu >= 85) $seconds = min($seconds, 1.5);
 elseif ($cpu >= 70) $seconds = min($seconds, 2.5);
 if ($disk >= 92) $seconds = min($seconds, 1.5);
 elseif ($disk >= 85) $seconds = min($seconds, 2.0);

 $chunks = $seconds <= 1.5 ? 2 : ($seconds <= 2.0 ? 3 : ($seconds <= 2.5 ? 4 : 6));
 return ['max_step_seconds' => $seconds, 'max_chunks' => $chunks];
}

function calculate_adaptive_chunk_size(PDO $pdo, string $db_name, string $table)
: int {
 if (!is_db_identifier_safe($table)) return max(75, get_dynamic_insert_batch_size());

 $base = 800;
 try {
 $stmt = $pdo->prepare("SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?");
 $stmt->execute([$db_name, $table]);
 $rows = (int)($stmt->fetchColumn() ?? 0);
 $stmt->closeCursor();
 if ($rows > 500000) $base = 5000;
 elseif ($rows > 100000) $base = 2500;
 elseif ($rows > 10000) $base = 1500;
 } catch (Throwable $e) {
 $base = 800;
 }

 $p = get_dynamic_resource_profile();
 $ram = (int)($p['operation_ram_budget_bytes'] ?? 32 * 1024 * 1024);
 $cpu = (float)($p['cpu_pressure_percent'] ?? 0);

 if ($ram < 64 * 1024 * 1024) $base = min($base, 150);
 elseif ($ram < 128 * 1024 * 1024) $base = min($base, 300);
 elseif ($ram < 256 * 1024 * 1024) $base = min($base, 600);
 elseif ($ram < 384 * 1024 * 1024) $base = min($base, 1000);

 if ($cpu >= 85) $base = (int)floor($base * 0.50);
 elseif ($cpu >= 70) $base = (int)floor($base * 0.70);
 elseif ($cpu < 35 && $ram >= 512 * 1024 * 1024) $base = (int)min(5000, round($base * 1.15));

 return max(75, min(5000, $base));
}

// =============================================================================
// PHP - ORTAK İŞLEM KİLİTLERİ
// Aynı anda iki yedekleme, geri yükleme veya tehlikeli veri tabanı işleminin
// birbirine karışmasını önlemek için burada kilit mekanizması kullanılır.
// =============================================================================

function acquire_system_lock(string $backup_dir, string $type = 'general', int $timeout = 60)
: mixed {
 $lock_file = $backup_dir . '/' . $type . '.lock';
 $fp = @fopen($lock_file, 'c+');
 if (!$fp) return false;

 $timeout = max(0, $timeout);
 $deadline = microtime(true) + $timeout;
 $current_host = gethostname() ?: 'host';
 $current_pid = getmypid() ?: 0;

 // flock() sahip olduğu bir kilittir; süreç ölürse işletim sistemi kilidi bırakır.
 // Bu nedenle dosyadaki eski PID/canlılık bilgisi bilgisini kullanarak zorla kilit
 // devralmak güvenli değildir. Bunun yerine gerçek bir sınırlı wait uygula.
 do {
 if (@flock($fp, LOCK_EX | LOCK_NB)) {
 break;
 }

 if (microtime(true) >= $deadline) {
 @fclose($fp);
 return false;
 }

 usleep(100000); // 100 ms durumu tekrar sorma; zaman aşımı boyunca CPU tüketimini düşük tut.
 } while (true);

 $now = time();
 ftruncate($fp, 0);
 rewind($fp);
 $meta = json_encode([
 'time' => $now,
 'started_at' => $now,
 'last_heartbeat' => $now,
 'pid' => $current_pid,
 'host' => $current_host
 ], JSON_UNESCAPED_SLASHES);
 if ($meta === false) {
 @flock($fp, LOCK_UN);
 @fclose($fp);
 return false;
 }
 $metaWritten = 0;
 $metaLength = strlen($meta);
 while ($metaWritten < $metaLength) {
 $written = @fwrite($fp, substr($meta, $metaWritten));
 if ($written === false || $written === 0) {
 @flock($fp, LOCK_UN);
 @fclose($fp);
 return false;
 }
 $metaWritten += $written;
 }
 if (!@fflush($fp)) {
 @flock($fp, LOCK_UN);
 @fclose($fp);
 return false;
 }

 return $fp;
}
function update_system_lock_heartbeat(mixed $lock_fp)
: void {
 static $last_update_times = [];
 $now = time();

 if (!is_resource($lock_fp)) {
 return;
 }

 $resourceId = (int)$lock_fp;
 $lastUpdate = (int)($last_update_times[$resourceId] ?? 0);

 if (($now - $lastUpdate) < 5 && $lastUpdate !== 0) {
 return;
 }

 rewind($lock_fp);
 $content = '';
 while (($line = fgets($lock_fp)) !== false) {
 $content .= $line;
 }

 $data = json_decode($content, true);
 if (!is_array($data)) {
 $data = [
 'started_at' => $now,
 'pid' => getmypid() ?: 0,
 'host' => gethostname() ?: 'host'
 ];
 }

 $data['last_heartbeat'] = $now;
 $data['time'] = $now;

 ftruncate($lock_fp, 0);
 rewind($lock_fp);
 fwrite($lock_fp, json_encode($data, JSON_UNESCAPED_SLASHES));
 fflush($lock_fp);

 $last_update_times[$resourceId] = $now;
}
function release_system_lock(mixed $lock_fp)
: void {
 if (is_resource($lock_fp)) {
 flock($lock_fp, LOCK_UN);
 fclose($lock_fp);
 }
}

function heartbeat_web_worker_locks()
: void {
 foreach ([
 'VEDO_WEB_WORKER_JOB_LOCK_HANDLE',
 'VEDO_WEB_WORKER_DB_LOCK_HANDLE'
 ] as $globalName) {
 if (isset($GLOBALS[$globalName]) && is_resource($GLOBALS[$globalName])) {
 update_system_lock_heartbeat($GLOBALS[$globalName]);
 }
 }
}
function with_database_operation_lock(string $backup_dir, int $timeout, callable $callback)
: mixed {
 $admission_lock = acquire_job_admission_lock($backup_dir);
 if (!$admission_lock) {
 throw new Exception('Başka bir veritabanı işlemi başlatılıyor. Yeni işlem başlatılamaz.');
 }
 $lock_handle = null;
 try {
 assert_restore_maintenance_marker_valid($backup_dir);
 assert_no_active_database_job($backup_dir);
 $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $timeout);
 if (!$lock_handle) {
 throw new Exception('Başka bir veritabanı işlemi aktif. Yeni işlem başlatılamaz.');
 }
 require_database_operation_lock($lock_handle, $backup_dir);
 update_system_lock_heartbeat($lock_handle);
 return $callback();
 } finally {
 if (is_resource($lock_handle)) release_system_lock($lock_handle);
 release_job_admission_lock($admission_lock);
 }
}
function require_database_operation_lock(mixed $lock_handle, string $backup_dir)
: void {
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
function safe_transaction_rollback(?PDO $pdo)
: void {
 if ($pdo instanceof PDO && $pdo->inTransaction()) {
 try {
 $pdo->rollBack();
 } catch (Exception $e) {
 Logger::error("Rollback hatası: " . $e->getMessage());
 }
 }
}
function limit_backup_files(string $dir, int $max)
: void {
 $real_backup_dir = realpath($dir);
 if (!$real_backup_dir) return;

 $sql_files = [];

 try {
 $iterator = new DirectoryIterator($real_backup_dir);
 foreach ($iterator as $fileinfo) {
 if ($fileinfo->isDot() || !$fileinfo->isFile()) continue;

 $filename = $fileinfo->getFilename();

 if (str_ends_with($filename, '.sql.gz') && !is_emergency_backup_filename($filename)) {
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
 usort($sql_files, static function (array $a, array $b): int {
 $mtimeCmp = ($a['mtime'] ?? 0) <=> ($b['mtime'] ?? 0);
 if ($mtimeCmp !== 0) return $mtimeCmp;
 return strcmp((string)($a['path'] ?? ''), (string)($b['path'] ?? ''));
 });
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
function escape_string_safe(mixed $v, ?PDO $pdo = null)
: string {
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
 if (!vedo_utf8_valid($v) || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $v)) {
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
/**
 * Veri tabanı bağlantısını açar veya uygun olduğunda yeniden kullanır. Hata olursa üst bölüme bildirir.
 */

// =============================================================================
// PHP - MYSQL BAĞLANTISI

/*
PDO VE MYSQL İLETİŞİMİ
Bu bölüm ile PHP'nin MySQL sunucusuyla konuşması sağlanır.

Öğrencinin aklında tutması gereken model:
PHP kodu doğrudan veritabanının içine girmez.
PDO bir "köprü" gibi davranır:

PHP → PDO → MySQL → sonuç → PDO → PHP

Burada bağlantı kurulurken sunucu adı, kullanıcı, şifre ve veritabanı
adı kullanılır. Daha sonra sorgular PDO üzerinden çalıştırılır.

Neden PDO?
- MySQL ile düzenli ve standart bir bağlantı arayüzü sağlar.
- Hata yönetimi ve prepared statement gibi güvenlik/sağlamlık
 özelliklerini kullanmaya izin verir.
*/

// Bu bölüm PDO kullanarak MySQL'e bağlanır. Bağlantı ayarları yukarıdaki $config
// dizisinden gelir ve hata oluşursa kontrollü biçimde bildirilir.
// =============================================================================

/*
 * ADIM ADIM: VERİTABANI BAĞLANTISI
 * 1) PDO için bağlantı bilgilerini hazırlar.
 * 2) MySQL sunucusuna bağlantı kurar.
 * 3) Hata oluşursa uygulamanın hata yönetimine bırakır.
 * 4) Hazırlanan PDO nesnesini çağıran bölüme verir.
 * Neden? Her sorgu öncesinde yeniden bağlantı kodu yazmak yerine
 * tek bir bağlantı fonksiyonu kullanmak kodu düzenli tutar.
 */
function get_pdo(string $h, string $u, string $p, string $d, bool $force_reconnect = false, bool $use_persistent = false)
: PDO {
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
 PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
 PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
 PDO::ATTR_TIMEOUT => 60,
 PDO::ATTR_EMULATE_PREPARES => false,
 PDO::ATTR_PERSISTENT => (bool)$use_persistent
 ];

 $pdo = new PDO($dsn, $u, $p, $options);
 $pdo->exec("SET SESSION sql_mode = REPLACE(@@sql_mode, 'NO_BACKSLASH_ESCAPES', '')");
 $instances[$key] = $pdo;
 $last_pings[$key] = microtime(true);

 return $instances[$key];
}
function get_database_size_bytes(PDO $pdo, string $db_name)
: ?int {
 try {
 $stmt = $pdo->prepare("SELECT COALESCE(SUM(COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)), 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?");
 $stmt->execute([$db_name]);
 $value = $stmt->fetchColumn();
 $stmt->closeCursor();

 // NULL, boş sonuç veya sayısal olmayan değer veri tabanı boyutunun
 // güvenilir biçimde hesaplanamadığı anlamına gelir. 0 döndürmek
 // tehlikelidir; büyük bir veritabanını yanlışlıkla "küçük" kabul ettirir.
 if ($value === false || $value === null || !is_numeric((string)$value)) {
 return null;
 }

 $size = (float)$value;
 if ($size < 0 || $size > PHP_INT_MAX) {
 return null;
 }

 return (int)round($size);
 } catch (Throwable $e) {
 Logger::warning('Veritabanı boyutu hesaplanamadı: ' . $e->getMessage());
 return null;
 }
}
function check_sufficient_disk_space(PDO $pdo, string $db_name, string $dir, int $extra_bytes = 0)
: void {
 $free_space = @disk_free_space($dir);
 if ($free_space === false) {
 throw new Exception('Disk boş alanı okunamadı; yedekleme/geri yükleme güvenlik nedeniyle başlatılmadı.');
 }

 $db_size = get_database_size_bytes($pdo, $db_name);
 if ($db_size === null) {
 throw new Exception('Veritabanı boyutu güvenilir biçimde hesaplanamadı. Disk alanı kontrolü doğrulanmadan işlem devam ettirilmiyor.');
 }

 $diskSafety = get_dynamic_disk_safety_bytes($dir);
 $dataWorking = max(256 * 1024 * 1024, (int)ceil($db_size * 1.25));
 $estimated_needed = $dataWorking + $diskSafety + max(0, $extra_bytes);

 if ($free_space < $estimated_needed) {
 throw new Exception(
 "Yetersiz disk alanı.\n" .
 "Boş Alan : " . format_bytes($free_space) . "\n" .
 "Gerekli : " . format_bytes($estimated_needed) . "\n" .
 "Otomatik güvenlik payı: " . format_bytes($diskSafety) . "\n" .
 ($extra_bytes > 0 ? "Ek geçici alan: " . format_bytes($extra_bytes) . "\n" : '')
 );
 }
}
/** Linux /proc/meminfo içeriğini tek okumada sayısal KB değerlerine dönüştürür. */

function read_proc_meminfo_kb(int $cacheTtlSeconds = 0)
: array {
 static $cache = null;
 static $cacheTime = 0;
 $cacheTtlSeconds = max(0, $cacheTtlSeconds);
 if ($cacheTtlSeconds > 0 && $cache !== null && (microtime(true) - $cacheTime) < $cacheTtlSeconds) {
 return $cache;
 }
 $result = [];
 if (!is_readable('/proc/meminfo')) return $result;

 $content = @file_get_contents('/proc/meminfo');
 if ($content === false) return $result;

 if (preg_match_all('/^([A-Za-z_]+):\s+(\d+)\s*kB\s*$/m', $content, $matches, PREG_SET_ORDER)) {
 foreach ($matches as $match) {
 $result[$match[1]] = (int)$match[2];
 }
 }
 if ($cacheTtlSeconds > 0) {
 $cache = $result;
 $cacheTime = microtime(true);
 }
 return $result;
}

function parse_ini_size_bytes(?string $value)
: int {
 $value = trim((string)$value);
 if ($value === '' || $value === '-1') return 0;
 if (!preg_match('/^(\d+(?:\.\d+)?)([KMG])?$/i', $value, $m)) {
 return 0;
 }
 $number = (float)$m[1];
 $multiplier = match(strtoupper($m[2] ?? '')) {
 'G' => 1024 ** 3,
 'M' => 1024 ** 2,
 'K' => 1024,
 default => 1
 };
 return (int)max(0, round($number * $multiplier));
}

function get_available_server_memory_bytes()
: int {
 // Dinamik PHP memory_limit hesabı için de aynı RAM kaynağını kullan.
 // Önce sunucunun ve varsa containerın kullanılabilir RAM bilgisini alır;
 // okunamazsa güvenli bir yedek yöntem kullanılır. Bu fonksiyon get_accurate_ram_metrics()
 // tarafından tekrar çağrılmadığı için sonsuz döngü oluşmaz.
 $memInfo = read_proc_meminfo_kb(2);
 $procAvailable = 0;
 if ($memInfo !== []) {
 if (isset($memInfo['MemAvailable'])) {
 $procAvailable = (int)$memInfo['MemAvailable'] * 1024;
 } else {
 $procAvailable = (
 (int)($memInfo['MemFree'] ?? 0) +
 (int)($memInfo['Buffers'] ?? 0) +
 (int)($memInfo['Cached'] ?? 0)
 ) * 1024;
 }
 }

 $cgroup = read_cgroup_memory_stats();
 if ($cgroup !== null) {
 $limit = (int)($cgroup['limit_bytes'] ?? 0);
 $current = $cgroup['current_bytes'];
 if ($limit > 0) {
 $procTotal = (int)($memInfo['MemTotal'] ?? 0) * 1024;
 $effectiveTotal = $procTotal > 0 ? min($procTotal, $limit) : $limit;
 if ($current !== null) {
 return max(0, $effectiveTotal - min($effectiveTotal, max(0, (int)$current)));
 }
 return max(0, min($effectiveTotal, $procAvailable));
 }
 }

 if ($procAvailable > 0) return $procAvailable;

 if (PHP_OS_FAMILY === 'Windows' && function_exists('exec')) {
 $psOut = [];
 $exitCode = 1;
 @exec('powershell -NoProfile -Command "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory"', $psOut, $exitCode);
 if ($exitCode === 0 && isset($psOut[0]) && is_numeric(trim($psOut[0]))) {
 $windowsAvailable = (int)trim($psOut[0]) * 1024;
 if ($windowsAvailable > 0) return $windowsAvailable;
 }
 }

 $iniBytes = parse_ini_size_bytes(ini_get('memory_limit'));
 return $iniBytes > 0 ? $iniBytes : 512 * 1024 * 1024;
}
function calculate_dynamic_memory_limit(PDO $pdo, string $db_name)
: string {
 $currentIni = (string)(ini_get('memory_limit') ?: '');
 $currentBytes = parse_ini_size_bytes($currentIni);
 $profile = get_dynamic_resource_profile();
 $total = (int)($profile['ram_total_bytes'] ?? 0);
 $free = (int)($profile['ram_free_bytes'] ?? 0);

 // Host bir memory_limit vermişse ona dokunma. Unlimited ise sunucu kapasitesinden
 // güvenli bir PHP tavanı türetmeyi dene; asıl çalışma anı koruması Kaynak Yöneticisi'dadır.
 if ($currentBytes <= 0 && $total > 0) {
 $recommended = (int)max(128 * 1024 * 1024, min($total * 0.70, max($free * 0.60, 128 * 1024 * 1024)));
 $limitStr = ceil($recommended / (1024 * 1024)) . 'M';
 if (@ini_set('memory_limit', $limitStr) !== false) return $limitStr;
 Logger::warning("memory_limit otomatik olarak '{$limitStr}' yapılandırılamadı; Resource Governor aktif kalacak.");
 }
 return $currentIni !== '' ? $currentIni : 'N/A';
}
function init_pdo_with_dynamic_memory(array &$config)
: PDO {
 static $initialized = false;
 $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);

 if (!$initialized) {
 calculate_dynamic_memory_limit($pdo, $config['db_name']);
 $initialized = true;
 }
 return $pdo;
}
function get_table_columns(?PDO $pdo, string $db_name, string $table)
: string {
 $cache_key = "cols.{$db_name}.{$table}";
 $cached = SchemaCache::get($cache_key);
 if ($cached !== null) return $cached;
 if ($pdo === null) throw new Exception("Şema okunamıyor: PDO bağlantısı yok.");

 try {
 $stmt = $pdo->prepare("
 SELECT COLUMN_NAME
 FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = ?
 AND TABLE_NAME = ?
 AND UPPER(COALESCE(EXTRA, '')) NOT LIKE 'VIRTUAL GENERATED%'
 AND UPPER(COALESCE(EXTRA, '')) NOT LIKE 'STORED GENERATED%'
 AND UPPER(COALESCE(EXTRA, '')) NOT LIKE 'PERSISTENT GENERATED%'
 ORDER BY ORDINAL_POSITION ASC
 ");
 $stmt->execute([$db_name, $table]);
 $cols = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 $formatted = !empty($cols)
 ? implode(', ', array_map(fn($c) => "`" . str_replace("`", "``", $c) . "`", $cols))
 : '';
 SchemaCache::set($cache_key, $formatted);
 return $formatted;
 } catch (Exception $e) {
 Logger::error("get_table_columns hatası ($table): " . $e->getMessage());
 }

 throw new Exception("Tablo şeması okunamadı [{$table}]. Yedekleme durduruldu!");
}
function get_table_cursor_keys(?PDO $pdo, string $db_name, string $table)
: array {
 $cache_key = "keys.{$db_name}.{$table}";
 $cached = SchemaCache::get($cache_key);
 if ($cached !== null) return $cached;
 if ($pdo === null) return [];

 try {
 // PRIMARY KEY tamamen güvenli bir keyset imlecidir. Fakat otomatik oluşturulan sütun
 // PRIMARY KEY'nin bir parçasıysa otomatik oluşturulan alanı çıkartıp kısmi bir anahtar
 // oluşturmak benzersizliği bozabilir ve satır atlamaya neden olabilir.
 $stmt = $pdo->prepare(<<<'SQL'
SELECT k.COLUMN_NAME,
 k.ORDINAL_POSITION,
 UPPER(COALESCE(c.EXTRA, '')) AS EXTRA_FLAGS
FROM information_schema.KEY_COLUMN_USAGE k
JOIN information_schema.COLUMNS c
 ON k.TABLE_SCHEMA = c.TABLE_SCHEMA
 AND k.TABLE_NAME = c.TABLE_NAME
 AND k.COLUMN_NAME = c.COLUMN_NAME
WHERE k.TABLE_SCHEMA = ?
 AND k.TABLE_NAME = ?
 AND k.CONSTRAINT_NAME = 'PRIMARY'
ORDER BY k.ORDINAL_POSITION ASC
SQL
 );
 $stmt->execute([$db_name, $table]);
 $primary = $stmt->fetchAll(PDO::FETCH_ASSOC);
 $stmt->closeCursor();

 if (!empty($primary)) {
 foreach ($primary as $row) {
 if (str_contains((string)($row['EXTRA_FLAGS'] ?? ''), 'GENERATED')) {
 Logger::warning("Generated column PRIMARY KEY içinde; {$table} için offset pagination fallback kullanılacak.");
 SchemaCache::set($cache_key, []);
 return [];
 }
 }

 $primaryCols = array_values(array_filter(array_map(
 static fn(array $row): string => (string)($row['COLUMN_NAME'] ?? ''),
 $primary
 ), static fn(string $name): bool => $name !== ''));
 if ($primaryCols !== []) {
 SchemaCache::set($cache_key, $primaryCols);
 return $primaryCols;
 }
 }

 // PRIMARY KEY yoksa yalnızca tam kapsamlı, NOT NULL ve otomatik oluşturulan olmayan
 // UNIQUE index'ler anahtar ile ilerleme adayıdır. Bir index'in tek kolonu bile
 // otomatik oluşturulan/boş olabilir/baş kısmı ise index'in tamamı reddedilir.
 $stmt = $pdo->prepare(<<<'SQL'
SELECT s.INDEX_NAME,
 s.COLUMN_NAME,
 s.SEQ_IN_INDEX,
 s.SUB_PART,
 c.IS_NULLABLE,
 UPPER(COALESCE(c.EXTRA, '')) AS EXTRA_FLAGS
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
SQL
 );
 $stmt->execute([$db_name, $table]);
 $unique_indexes = [];
 while ($row = $stmt->
/*
 * JAVASCRIPT FETCH AKIŞI
 * fetch() tarayıcıdan PHP'ye HTTP isteği göndermek için kullanılır.
 *
 * Genel akış:
 * 1) Kullanıcı butona basar.
 * 2) JavaScript fetch() çağırır.
 * 3) PHP isteği alır ve action değerine göre işlem yapar.
 * 4) PHP genellikle JSON cevap döndürür.
 * 5) JavaScript cevabı okur.
 * 6) Sonucu ekrandaki ilgili HTML elemanına yazar.
 *
 * Böylece sayfanın tamamını yeniden yüklemeden arayüz güncellenebilir.
 */
fetch(PDO::FETCH_ASSOC)) {
 $indexName = (string)($row['INDEX_NAME'] ?? '');
 if ($indexName === '') continue;
 $unique_indexes[$indexName][] = [
 'column' => (string)($row['COLUMN_NAME'] ?? ''),
 'nullable' => strtoupper((string)($row['IS_NULLABLE'] ?? 'YES')) !== 'NO',
 'sub_part' => isset($row['SUB_PART']) && $row['SUB_PART'] !== null ? (int)$row['SUB_PART'] : null,
 'generated' => str_contains((string)($row['EXTRA_FLAGS'] ?? ''), 'GENERATED'),
 'seq' => (int)($row['SEQ_IN_INDEX'] ?? 0)
 ];
 }
 $stmt->closeCursor();

 foreach ($unique_indexes as $columns) {
 usort($columns, static fn(array $a, array $b): int => $a['seq'] <=> $b['seq']);
 if ($columns === []) continue;

 $unsafe = false;
 foreach ($columns as $column) {
 if (
 $column['nullable'] ||
 $column['column'] === '' ||
 $column['sub_part'] !== null ||
 $column['generated']
 ) {
 $unsafe = true;
 break;
 }
 }
 if ($unsafe) continue;

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

function format_duration_seconds(float|int $seconds)
: string {
 $total = max(0, (int)round($seconds));
 $hours = intdiv($total, 3600);
 $minutes = intdiv($total % 3600, 60);
 $secs = $total % 60;

 if ($hours > 0) {
 return sprintf('%dsa %02ddk %02dsn', $hours, $minutes, $secs);
 }

 return sprintf('%ddk %02dsn', $minutes, $secs);
}

function format_bytes(int|float $bytes, int $precision = 2)
: string {
 $units = ['B', 'KB', 'MB', 'GB', 'TB'];
 $bytes = max((float)$bytes, 0);
 $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
 $pow = min((int)$pow, count($units) - 1);
 $bytes /= pow(1024, $pow);
 return round($bytes, $precision) . ' ' . $units[$pow];
}
/**
 * İlerleme ekranında küçük hızları uygun birimle gösterir.
 */
function format_transfer_speed(float $bytesPerSecond)
: string {
 $bytesPerSecond = max(0.0, $bytesPerSecond);
 if ($bytesPerSecond >= 1073741824) return round($bytesPerSecond / 1073741824, 2) . ' GB/sn';
 if ($bytesPerSecond >= 1048576) return round($bytesPerSecond / 1048576, 2) . ' MB/sn';
 if ($bytesPerSecond >= 1024) return round($bytesPerSecond / 1024, 2) . ' KB/sn';
 return round($bytesPerSecond, 0) . ' B/sn';
}

/**
 * WEB yedek ve acil yedek için yaklaşık kalan süreyi hesaplar.
 * İlk tabloda geçmiş veri bulunmadığından ETA null olabilir; arayüz bu durumda "Hesaplanıyor…" gösterir.
 */
function calculate_web_backup_eta(array $state, int $currentIndexOneBased, int $totalTables, float $elapsedSeconds)
: ?int {
 if ($totalTables <= 0) return null;
 $currentIndexOneBased = max(1, min($currentIndexOneBased, $totalTables));
 $completedTables = $currentIndexOneBased - 1;
 $averageTableSeconds = $completedTables > 0 ? $elapsedSeconds / $completedTables : 0.0;
 $futureTables = max(0, $totalTables - $currentIndexOneBased);

 $tableState = is_array($state['web_table_state'] ?? null) ? $state['web_table_state'] : [];
 $estimatedRows = max(0, (int)($tableState['estimated_rows'] ?? 0));
 $currentRows = max(0, (int)($tableState['rows_for_table'] ?? 0));
 $tableStartedAt = (float)($tableState['table_started_at'] ?? 0);
 $currentElapsed = $tableStartedAt > 0 ? max(0.0, microtime(true) - $tableStartedAt) : 0.0;

 $currentEta = null;
 if ($estimatedRows > 0 && $currentRows > 0 && $currentRows < $estimatedRows && $currentElapsed > 0) {
 $ratio = min(0.99, $currentRows / $estimatedRows);
 $currentEta = $currentElapsed * ((1.0 - $ratio) / max($ratio, 0.01));
 } elseif ($averageTableSeconds > 0) {
 $currentEta = $averageTableSeconds;
 }

 if ($currentEta === null && $averageTableSeconds <= 0) return null;
 return max(1, (int)ceil(($currentEta ?? 0.0) + ($averageTableSeconds * $futureTables)));
}

function safe_gzwrite(mixed $stream, string $data, bool $flush = false)
: void {
 $length = strlen($data);
 if ($length === 0) return;

 // gzwrite() kısmi yazma döndürebilir. Tek çağrıyı "tam yazıldı" kabul etmek
 // büyük bloklarda gereksiz yedek alma hatasına yol açabilir. Kalan kısmı güvenli
 // biçimde tamamlayana kadar yazmayı sürdür.
 $offset = 0;
 $written = @gzwrite($stream, $data);
 if ($written === false || $written === 0) {
 throw new Exception("Gzip arşivine yazma başarısız oldu.");
 }
 $offset = $written;
 while ($offset < $length) {
 $written = @gzwrite($stream, substr($data, $offset));
 if ($written === false || $written === 0) {
 throw new Exception("Gzip arşivine yazma başarısız oldu.");
 }
 $offset += $written;
 }

 if ($flush && function_exists('gzflush')) {
 if (@gzflush($stream, ZLIB_SYNC_FLUSH) === false) {
 throw new Exception("Gzip arşivi flush edilemedi.");
 }
 }
}

/**
 * veri tabanı NESNELERİ DIŞA AKTARIMI (GÖRÜNÜM, TETİKLEYİCİ, PROSEDÜR, FONKSİYON, OLAY)
 */
function order_views_by_dependencies(PDO $pdo, string $db_name, array $views)
: array {
 $views = array_values(array_map('strval', $views));
 if (count($views) <= 1) return $views;

 $viewSet = array_fill_keys($views, true);
 $dependencies = array_fill_keys($views, []);

 try {
 $stmt = $pdo->prepare("
 SELECT VIEW_NAME, TABLE_NAME
 FROM information_schema.VIEW_TABLE_USAGE
 WHERE VIEW_SCHEMA = ? AND TABLE_SCHEMA = ?
 ");
 $stmt->execute([$db_name, $db_name]);

 while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
 $view = (string)($row['VIEW_NAME'] ?? '');
 $table = (string)($row['TABLE_NAME'] ?? '');
 if (isset($viewSet[$view]) && isset($viewSet[$table]) && $view !== $table) {
 $dependencies[$view][$table] = true;
 }
 }
 $stmt->closeCursor();
 } catch (Throwable $e) {
 Logger::warning('VIEW dependency metadata okunamadı; alfabetik sıra kullanılacak: ' . $e->getMessage());
 sort($views, SORT_STRING);
 return $views;
 }

 $inDegree = [];
 $children = array_fill_keys($views, []);
 foreach ($views as $view) {
 $inDegree[$view] = count($dependencies[$view]);
 }
 foreach ($dependencies as $view => $deps) {
 foreach (array_keys($deps) as $dep) {
 $children[$dep][] = $view;
 }
 }

 $queue = [];
 foreach ($views as $view) {
 if ($inDegree[$view] === 0) $queue[] = $view;
 }
 sort($queue, SORT_STRING);

 $ordered = [];
 while ($queue) {
 $current = array_shift($queue);
 $ordered[] = $current;

 $next = $children[$current] ?? [];
 sort($next, SORT_STRING);
 foreach ($next as $child) {
 $inDegree[$child]--;
 if ($inDegree[$child] === 0) {
 $queue[] = $child;
 }
 }
 sort($queue, SORT_STRING);
 }

 if (count($ordered) < count($views)) {
 $remaining = array_values(array_diff($views, $ordered));
 sort($remaining, SORT_STRING);
 $ordered = array_merge($ordered, $remaining);
 }

 return $ordered;
}

function order_routines_by_dependencies(PDO $pdo, string $db_name, array $routines, string $routine_type)
: array {
 $routines = array_values(array_map('strval', $routines));
 if (count($routines) <= 1) return $routines;
 $dependencies = array_fill_keys($routines, []);
 $column = strtoupper($routine_type) === 'FUNCTION' ? 'Create Function' : 'Create Procedure';
 $keyword = strtoupper($routine_type) === 'FUNCTION' ? 'FUNCTION' : 'PROCEDURE';

 foreach ($routines as $routine) {
 if (!is_db_identifier_safe($routine)) throw new Exception("Geçersiz {$routine_type} adı: {$routine}");
 $q='`'.str_replace('`','``',$routine).'`';
 $st=$pdo->query("SHOW CREATE {$keyword} {$q}");
 $row=$st?$st->fetch(PDO::FETCH_ASSOC):false;
 if($st)$st->closeCursor();
 $body=is_array($row)?(string)($row[$column]??''):'';
 if($body==='') throw new Exception("{$routine_type} tanımı okunamadı: {$routine}");
 foreach($routines as $candidate){
 if($candidate===$routine)continue;
 $cq=preg_quote($candidate,'/');
 if(preg_match('/(?:`'.$cq.'`|\b'.$cq.'\b)\s*\(/iu',$body) || preg_match('/\bCALL\s+(?:`'.$cq.'`|\b'.$cq.'\b)/iu',$body)){
 $dependencies[$routine][$candidate]=true;
 }
 }
 }
 $in=array_fill_keys($routines,0); $children=array_fill_keys($routines,[]);
 foreach($dependencies as $r=>$deps){$in[$r]=count($deps); foreach(array_keys($deps) as $d)$children[$d][]=$r;}
 $q=[]; foreach($routines as $r)if($in[$r]===0)$q[]=$r; sort($q,SORT_STRING);
 $ordered=[]; while($q){$cur=array_shift($q);$ordered[]=$cur; $next=$children[$cur]??[];sort($next,SORT_STRING);foreach($next as $ch){$in[$ch]--;if($in[$ch]===0)$q[]=$ch;}sort($q,SORT_STRING);}
 if(count($ordered)<count($routines)){$rem=array_values(array_diff($routines,$ordered));sort($rem,SORT_STRING);$ordered=array_merge($ordered,$rem);}
 return $ordered;
}

function export_database_sequences_to_stream(PDO $pdo, string $db_name, mixed $stream)
: int {
 $exported = 0;
 $stmt = $pdo->prepare("
 SELECT TABLE_NAME
 FROM information_schema.TABLES
 WHERE TABLE_SCHEMA = ?
 AND UPPER(COALESCE(ENGINE, '')) = 'SEQUENCE'
 ORDER BY TABLE_NAME
 ");
 $stmt->execute([$db_name]);
 $sequences = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($sequences as $sequence) {
 $sequence = (string)$sequence;
 if (!is_db_identifier_safe($sequence)) {
 throw new Exception("Geçersiz SEQUENCE adı dışa aktarılamadı: {$sequence}");
 }
 $q = '`' . str_replace('`', '``', $sequence) . '`';
 $sStmt = $pdo->query("SHOW CREATE SEQUENCE {$q}");
 $row = $sStmt ? $sStmt->fetch(PDO::FETCH_ASSOC) : false;
 if ($sStmt) $sStmt->closeCursor();
 $createSql = is_array($row) ? (string)($row['Create Sequence'] ?? $row['Create Table'] ?? '') : '';
 if ($createSql === '') {
 throw new Exception("SEQUENCE dışa aktarılamadı [{$sequence}]: SHOW CREATE SEQUENCE sonucu boş.");
 }
 safe_gzwrite($stream, "DROP SEQUENCE IF EXISTS {$q};
{$createSql};

");
 $exported++;
 }


 return $exported;
}


function export_database_objects_to_stream(PDO $pdo, string $db_name, mixed $stream)
: void {
 safe_gzwrite(
 $stream,
 "\n-- ==========================================\n" .
 "-- DATABASE OBJECTS (SEQUENCES, FUNCTIONS, PROCEDURES, VIEWS, TRIGGERS, EVENTS)\n" .
 "-- ==========================================\n\n"
 );

 $exported = [
 'views' => 0,
 'procedures' => 0,
 'functions' => 0,
 'triggers' => 0,
 'events' => 0,
 ];

 // FONKSİYONLAR
 $stmt = $pdo->prepare("SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'FUNCTION' ORDER BY ROUTINE_NAME");
 $stmt->execute([$db_name]);
 $funcs = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();
 $funcs = order_routines_by_dependencies($pdo, $db_name, $funcs, 'FUNCTION');

 foreach ($funcs as $func) {
 $func = (string)$func;
 if (!is_db_identifier_safe($func)) {
 throw new Exception("Geçersiz FUNCTION adı dışa aktarılamadı: {$func}");
 }

 $q = '`' . str_replace('`', '``', $func) . '`';
 $fStmt = $pdo->query("SHOW CREATE FUNCTION {$q}");
 $row = $fStmt ? $fStmt->fetch(PDO::FETCH_ASSOC) : false;
 if ($fStmt) $fStmt->closeCursor();

 $createSql = is_array($row) ? (string)($row['Create Function'] ?? '') : '';
 if ($createSql === '') {
 throw new Exception("SHOW CREATE FUNCTION sonucu boş.");
 }


 safe_gzwrite(
 $stream,
 "DROP FUNCTION IF EXISTS {$q};\n" .
 "DELIMITER //\n{$createSql} //\nDELIMITER ;\n\n"
 );
 $exported['functions']++;
 }

 // 3. PROSEDÜRLER
 $stmt = $pdo->prepare("SELECT ROUTINE_NAME FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? AND ROUTINE_TYPE = 'PROCEDURE' ORDER BY ROUTINE_NAME");
 $stmt->execute([$db_name]);
 $procs = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();
 $procs = order_routines_by_dependencies($pdo, $db_name, $procs, 'PROCEDURE');

 foreach ($procs as $proc) {
 $proc = (string)$proc;
 if (!is_db_identifier_safe($proc)) {
 throw new Exception("Geçersiz PROCEDURE adı dışa aktarılamadı: {$proc}");
 }

 $q = '`' . str_replace('`', '``', $proc) . '`';
 $pStmt = $pdo->query("SHOW CREATE PROCEDURE {$q}");
 $row = $pStmt ? $pStmt->fetch(PDO::FETCH_ASSOC) : false;
 if ($pStmt) $pStmt->closeCursor();

 $createSql = is_array($row) ? (string)($row['Create Procedure'] ?? '') : '';
 if ($createSql === '') {
 throw new Exception("SHOW CREATE PROCEDURE sonucu boş.");
 }


 safe_gzwrite(
 $stream,
 "DROP PROCEDURE IF EXISTS {$q};\n" .
 "DELIMITER //\n{$createSql} //\nDELIMITER ;\n\n"
 );
 $exported['procedures']++;
 }

 // 4. GÖRÜNÜMLER — Görünümler, birbirleri arasındaki bağımlılıklara göre sıralanır.
 $stmt = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'VIEW'");
 $stmt->execute([$db_name]);
 $views = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach (order_views_by_dependencies($pdo, $db_name, $views) as $view) {
 $view = (string)$view;
 if (!is_db_identifier_safe($view)) {
 throw new Exception("Geçersiz VIEW adı dışa aktarılamadı: {$view}");
 }

 $q = '`' . str_replace('`', '``', $view) . '`';
 $vStmt = $pdo->query("SHOW CREATE VIEW {$q}");
 $row = $vStmt ? $vStmt->fetch(PDO::FETCH_ASSOC) : false;
 if ($vStmt) $vStmt->closeCursor();

 $createSql = is_array($row) ? (string)($row['Create View'] ?? '') : '';
 if ($createSql === '') {
 throw new Exception("SHOW CREATE VIEW sonucu boş.");
 }


 safe_gzwrite($stream, "DROP VIEW IF EXISTS {$q};\n{$createSql};\n\n");
 $exported['views']++;
 }

 // 5. TETİKLEYİCİLER
 $stmt = $pdo->prepare("SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ? ORDER BY TRIGGER_NAME");
 $stmt->execute([$db_name]);
 $triggers = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($triggers as $trig) {
 $trig = (string)$trig;
 if (!is_db_identifier_safe($trig)) {
 throw new Exception("Geçersiz TRIGGER adı dışa aktarılamadı: {$trig}");
 }

 $q = '`' . str_replace('`', '``', $trig) . '`';
 $tStmt = $pdo->query("SHOW CREATE TRIGGER {$q}");
 $row = $tStmt ? $tStmt->fetch(PDO::FETCH_ASSOC) : false;
 if ($tStmt) $tStmt->closeCursor();

 $createSql = is_array($row)
 ? (string)($row['SQL Original Statement'] ?? $row['Create Trigger'] ?? '')
 : '';

 if ($createSql === '') {
 throw new Exception("SHOW CREATE TRIGGER sonucu boş.");
 }


 safe_gzwrite(
 $stream,
 "DROP TRIGGER IF EXISTS {$q};\n" .
 "DELIMITER //\n{$createSql} //\nDELIMITER ;\n\n"
 );
 $exported['triggers']++;
 }

 // 6. OLAYLAR
 $stmt = $pdo->prepare("SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ? ORDER BY EVENT_NAME");
 $stmt->execute([$db_name]);
 $events = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($events as $ev) {
 $ev = (string)$ev;
 if (!is_db_identifier_safe($ev)) {
 throw new Exception("Geçersiz EVENT adı dışa aktarılamadı: {$ev}");
 }

 $q = '`' . str_replace('`', '``', $ev) . '`';
 $eStmt = $pdo->query("SHOW CREATE EVENT {$q}");
 $row = $eStmt ? $eStmt->fetch(PDO::FETCH_ASSOC) : false;
 if ($eStmt) $eStmt->closeCursor();

 $createSql = is_array($row) ? (string)($row['Create Event'] ?? '') : '';
 if ($createSql === '') {
 throw new Exception("SHOW CREATE EVENT sonucu boş.");
 }


 safe_gzwrite(
 $stream,
 "DROP EVENT IF EXISTS {$q};\n" .
 "DELIMITER //\n{$createSql} //\nDELIMITER ;\n\n"
 );
 $exported['events']++;
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
 * Tabloda uygun bir anahtar yoksa satırların hep aynı sırada gelmesini sağlayan başka bir sıralama seçer. Böylece satır atlama veya tekrar etme riski azalır.
 */
// anahtar ile ilerleme kullanılamayan tablolar için deterministik kolon sırası üretir. Şema önbellek kullanılır.
function get_table_fallback_order_by(PDO $pdo, string $db_name, string $table)
: string {
 if (!is_db_identifier_safe($table)) {
 throw new Exception("Geçersiz tablo adı.");
 }

 $cacheKey = "fallback_order.{$db_name}.{$table}";
 $cached = SchemaCache::get($cacheKey);
 if (is_string($cached) && $cached !== '') return $cached;

 $stmt = $pdo->prepare("
 SELECT COLUMN_NAME
 FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = ?
 AND TABLE_NAME = ?
 AND UPPER(COALESCE(EXTRA, '')) NOT LIKE 'VIRTUAL GENERATED%'
 AND UPPER(COALESCE(EXTRA, '')) NOT LIKE 'STORED GENERATED%'
 AND UPPER(COALESCE(EXTRA, '')) NOT LIKE 'PERSISTENT GENERATED%'
 ORDER BY ORDINAL_POSITION ASC
 ");
 $stmt->execute([$db_name, $table]);
 $columns = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 if (empty($columns)) {
 throw new Exception("Tablo için sıralanabilir kolon bulunamadı: {$table}");
 }

 $orderBy = implode(', ', array_map(
 static fn($column): string => '`' . str_replace('`', '``', (string)$column) . '`',
 $columns
 ));
 SchemaCache::set($cacheKey, $orderBy);
 return $orderBy;
}

/**
 * TEK TABLODAN SADECE OKUYARAK YEDEK ALMA
 */
function export_single_table_to_stream(PDO $pdo, string $table, mixed $stream, string $db_name, int &$processed_total_rows, ?callable $on_progress = null, int $max_insert_rows = 500)
: void {
 if (!is_db_identifier_safe($table)) {
 throw new Exception("Geçersiz tablo tanımı tespit edildi.");
 }

 $stmtInfo = $pdo->prepare("SHOW CREATE TABLE `{$table}`");
 $stmtInfo->execute();
 $createTableStmt = $stmtInfo->fetch();
 $stmtInfo->closeCursor();

 $createTableSql = $createTableStmt['Create Table'] ?? $createTableStmt['Create View'] ?? '';


 $schema_sql = "\nDROP TABLE IF EXISTS `{$table}`;\n" . $createTableSql . ";\n\n";
 $is_view = isset($createTableStmt['Create View']);

 safe_gzwrite($stream, $schema_sql);

 if ($is_view) return;

 $chunk_size = calculate_adaptive_chunk_size($pdo, $db_name, $table);
 $dynamic_batch_size = get_dynamic_insert_batch_size();
 $columns_select = get_table_columns($pdo, $db_name, $table);
 if ($columns_select === '') {
 // Tüm kolonlar otomatik oluşturulan ise explicit empty-column INSERT ile satır sayısını koru.
 $countStmt = $pdo->query("SELECT COUNT(*) FROM `{$table}`");
 $rowCount = $countStmt ? (int)$countStmt->fetchColumn() : 0;
 if ($countStmt) $countStmt->closeCursor();

 $processed = 0;
 $batchSize = $dynamic_batch_size;
 while ($processed < $rowCount) {
 $batch = min($batchSize, $rowCount - $processed);
 $rows = array_fill(0, $batch, '()');
 safe_gzwrite($stream, "INSERT INTO `{$table}` () VALUES\n" . implode(",\n", $rows) . ";\n");
 $processed += $batch;
 $processed_total_rows += $batch;
 }
 if (is_callable($on_progress)) call_user_func($on_progress);
 return;
 }
 $cursor_keys = get_table_cursor_keys($pdo, $db_name, $table);

 $use_keyset = !empty($cursor_keys);
 $key_count = count($cursor_keys);
 $quoted_keys = array_map(fn($k) => "`$k`", $cursor_keys);
 $order_by_clause = $use_keyset ? implode(', ', $quoted_keys) : '';

 $last_values = null;
 $offset = 0;
 $total_exported_rows = 0;
 $write_counter = 0;
 // Keyset kullanılamayan tablo için şema sorgusunu her parça'ta tekrarlama.
 $fallbackOrder = $use_keyset ? '' : get_table_fallback_order_by($pdo, $db_name, $table);

 $max_insert_rows = $dynamic_batch_size;
 $max_buffer_bytes = get_dynamic_export_buffer_bytes();

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
 $stmt = $pdo->prepare("SELECT {$columns_select} FROM `{$table}` ORDER BY {$fallbackOrder} LIMIT :offset, :limit");
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
 safe_gzwrite($stream, "INSERT INTO `{$table}` ({$columns_select}) VALUES\n" . implode(",\n", $rows_buffer) . ";\n", $should_flush);
 $rows_buffer = [];
 $rows_buffer_bytes = 0;
 }
 }

 if (!empty($rows_buffer)) {
 $write_counter++;
 $should_flush = ($write_counter % 10 === 0);
 safe_gzwrite($stream, "INSERT INTO `{$table}` ({$columns_select}) VALUES\n" . implode(",\n", $rows_buffer) . ";\n", $should_flush);
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
 * YEDEKLEME ÖNCESİ MYISAM ONARIMI
 * Sadece MyISAM tablolarında REPAIR TABLE çalıştırır.
 * InnoDB ve diğer motorlara dokunmaz.
 */
function repair_myisam_tables_before_backup(PDO $pdo, string $db_name)
: void {
 $stmt = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND ENGINE = 'MyISAM' AND TABLE_TYPE = 'BASE TABLE'");
 $stmt->execute([$db_name]);
 $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($tables as $table) {
 $table = (string)$table;
 if ($table === '' || !is_db_identifier_safe($table)) {
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
 * MyISAM tabloları ayrı bir PDO bağlantısında READ kilidi altında tutulur.
 * Böylece ana PDO üzerindeki InnoDB tutarlı anlık görüntü işlemi ile tablo kilidi
 * birbirine karışmaz.
 */
function acquire_myisam_read_locks(string $h, string $u, string $p, string $d)
: array {
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
 if ($table === '' || !is_db_identifier_safe($table)) {
 throw new Exception("MyISAM tablo adı doğrulanamadı: {$table}");
 }
 $quoted[] = '`' . str_replace('`', '``', $table) . '`';
 }

 $lockPdo->exec("LOCK TABLES " . implode(", ", array_map(fn($t) => $t . " READ", $quoted)));
 Logger::info("MyISAM READ LOCK aktif: " . count($quoted) . " tablo.");
 return ['pdo' => $lockPdo, 'tables' => $quoted];
}
function release_myisam_read_locks(?PDO $lockPdo)
: void {
 if ($lockPdo instanceof PDO) {
 try {
 $lockPdo->exec("UNLOCK TABLES");
 } catch (Throwable $e) {
 Logger::warning("MyISAM READ LOCK bırakılamadı: " . $e->getMessage());
 }
 }
}

/**
 * ANA YEDEK ALMA MOTORU
 */
/**
 * Veritabanının tam yedeğini üretir. Tablo verileri ile VIEW, TRIGGER, PROCEDURE,
 * FUNCTION ve EVENT gibi nesneleri uygun sırada aktarır ve doğrulanabilir bir gzip yedeği oluşturur.
 */

// =============================================================================
// PHP - ANA YEDEKLEME MOTORU

/*
YEDEKLEME İŞLEMİNİN ANA AKIŞI
Bu bölüm uygulamanın en önemli bölümlerinden biridir.

Basitleştirilmiş akış:
1) Veritabanına bağlan.
2) Diskte yeterli alan var mı kontrol et.
3) Gerekli kilitleri al.
4) Tabloların yapısını ve verilerini oku.
5) SQL komutlarını .sql.gz dosyasına yaz.
6) İşlem sırasında ilerleme bilgisini güncelle.
7) Dosyanın SHA-256 özetini oluştur.
8) Yedeği doğrula.
9) Eski yedek sayısı sınırı aşılmışsa eski dosyaları temizle.
10) Kilitleri bırak.

Bu bölümdeki kodu okurken "tek seferde bütün veritabanını RAM'e almak"
yerine "veriyi parça parça okuyup dosyaya yazma" yaklaşımına dikkat edin.
Büyük veritabanlarında bu yaklaşım RAM kullanımını kontrol altında tutar.
*/

// Yedekleme işleminin ana akışı burada yönetilir: tablolar okunur, SQL oluşturulur,
// gzip ile sıkıştırılır, geçici dosya tamamlanınca gerçek yedek dosyasına çevrilir
// ve ardından SHA-256 kontrolü ile saklama/temizleme işlemleri yapılır.
// =============================================================================

function perform_backup(PDO $pdo, string $db_name, string $backup_dir, array $config, mixed $lock_handle, ?callable $progress_callback = null, string $filename_prefix = '', bool $apply_retention = true)
: string {
 require_database_operation_lock($lock_handle, $backup_dir);
 update_system_lock_heartbeat($lock_handle);

 $myisam_lock_pdo = null;
 $snapshot_started = false;
 $gz = null;
 $tmp_gz_file = '';
 $target_gz_file = '';
 $target_finalized = false;
 $progress_ready = false;
 $start_time = microtime(true);
 $processed_rows_total = 0;
 $table_index = 0;
 $total_tables = 0;

 $update_progress = static function (string $status, string $current_table = '', string $error_msg = '') use (&$table_index, &$total_tables, &$processed_rows_total, $start_time, &$tmp_gz_file, &$target_gz_file, $progress_callback): void {
 if ($progress_callback === null) return;
 try {
 $now = microtime(true);
 $elapsed = max(0.1, $now - $start_time);
 clearstatcache(true, $tmp_gz_file);
 $bytes_written = ($tmp_gz_file !== '' && is_file($tmp_gz_file))
 ? (int)filesize($tmp_gz_file)
 : (($target_gz_file !== '' && is_file($target_gz_file)) ? (int)filesize($target_gz_file) : 0);
 // table_index aktif tabloyu 1 tabanlı gösterir; yüzde yalnızca tamamlanan tabloları temsil eder.
 $completed_tables = $status === 'completed' ? $total_tables : max(0, $table_index - 1);
 $percent = ($total_tables > 0) ? min(99, (int)floor(($completed_tables / $total_tables) * 100)) : 0;
 if ($status === 'completed') $percent = 100;
 $rows_per_sec = (int)round($processed_rows_total / $elapsed);
 $bytes_per_sec = $bytes_written / $elapsed;
 $mb_per_sec = round($bytes_per_sec / 1048576, 2);
 $eta = ($completed_tables > 0 && $status !== 'completed')
 ? max(1, (int)ceil(($elapsed / $completed_tables) * max(0, $total_tables - $completed_tables)))
 : null;
 $progress_callback([
 'status' => $status,
 'percent' => $percent,
 'current_table' => $current_table,
 'current_table_index' => $table_index,
 'total_tables' => $total_tables,
 'processed_rows' => $processed_rows_total,
 'elapsed_seconds' => round($elapsed),
 'estimated_remaining_seconds' => $eta,
 'formatted_speed' => format_transfer_speed($bytes_per_sec),
 'speed_rows_per_second' => $rows_per_sec,
 'speed_mb_per_second' => $mb_per_sec,
 'bytes_written' => $bytes_written,
 'formatted_bytes' => format_bytes($bytes_written),
 'file_name' => $target_gz_file !== '' ? basename($target_gz_file) : '',
 'error_message' => $error_msg,
 'updated_at' => date('Y-m-d H:i:s')
 ]);
 } catch (Throwable $progressError) {
 Logger::warning('Backup progress callback başarısız; backup sonucunu geçersiz kılmayacak: ' . $progressError->getMessage());
 }
 };

 try {
 SchemaCache::clear();
 if (!empty($config['repair_myisam_before_backup'])) {
 repair_myisam_tables_before_backup($pdo, $db_name);
 update_system_lock_heartbeat($lock_handle);
 }

 check_sufficient_disk_space($pdo, $db_name, $backup_dir);
 $lock_info = acquire_myisam_read_locks(
 $config['db_host'], $config['db_user'], $config['db_pass'], $db_name
 );
 $myisam_lock_pdo = $lock_info['pdo'] ?? null;
 update_system_lock_heartbeat($lock_handle);

 $pdo->exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
/*
 * TUTARLI ANLIK GÖRÜNTÜ
 * Buradaki işlem, mümkün olduğunca aynı veri görünümünü koruyarak
 * yedek alınmasına yardımcı olur.
 *
 * Kısa açıklama:
 * Veritabanı yedekleme sadece SELECT çalıştırmak değildir. Yedek
 * alınırken başka işlemler de gerçekleşebilir. Transaction/snapshot
 * yaklaşımı, okunan verilerin birbiriyle daha tutarlı olmasını sağlar.
 */
 $pdo->exec("START TRANSACTION WITH CONSISTENT SNAPSHOT");
 $snapshot_started = true;
 update_system_lock_heartbeat($lock_handle);

 $stmtTables = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' AND UPPER(COALESCE(ENGINE, '')) <> 'SEQUENCE' ORDER BY TABLE_NAME");
 $stmtTables->execute([$db_name]);
 $tables = $stmtTables->fetchAll(PDO::FETCH_COLUMN);
 $stmtTables->closeCursor();
 $total_tables = count($tables);

 $backup_time_string = gmdate('Y-m-d_H-i') . 'UTC';
 $safePrefix = $filename_prefix !== '' ? trim($filename_prefix, '_') . '_' : '';
 $base_gz_file = $backup_dir . '/' . $safePrefix . $db_name . '_' . $backup_time_string;
 $target_gz_file = $base_gz_file . '.sql.gz';
 $dup_counter = 1;
 while (file_exists($target_gz_file)) {
 $target_gz_file = $base_gz_file . '_' . $dup_counter . '.sql.gz';
 $dup_counter++;
 }
 $tmp_gz_file = $target_gz_file . '.tmp';

 $gz_level = max(0, min(9, get_dynamic_system_load()));
 $gz = @gzopen($tmp_gz_file, "w{$gz_level}");
 if (!$gz) throw new Exception('Geçici sıkıştırılmış yedek dosyası oluşturulamadı.');
 $progress_ready = true;

 $update_progress('running', $tables[0] ?? '');
 safe_gzwrite($gz, "-- VEDO MYSQL BACKUP [FORMAT v" . VEDO_BACKUP_FORMAT . "]\n-- DB: {$db_name}\n-- TIME: " . date('Y-m-d H:i:s') . "\n-- CONSISTENT SNAPSHOT: REPEATABLE READ / WITH CONSISTENT SNAPSHOT\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n\n");

 $sequenceCount = export_database_sequences_to_stream($pdo, $db_name, $gz);
 safe_gzwrite($gz, "-- SEQUENCES EXPORTED BEFORE TABLES: {$sequenceCount}\n\n");
 update_system_lock_heartbeat($lock_handle);

 foreach ($tables as $table) {
 $table_index++;
 update_system_lock_heartbeat($lock_handle);
 $update_progress('running', (string)$table);
 export_single_table_to_stream(
 $pdo,
 (string)$table,
 $gz,
 $db_name,
 $processed_rows_total,
 static function () use (&$update_progress, $table): void { $update_progress('running', (string)$table); },
 get_dynamic_insert_batch_size($backup_dir)
 );
 }

 $update_progress('running', 'Database Objects (Views/Triggers/Functions)');
 export_database_objects_to_stream($pdo, $db_name, $gz);

 if ($snapshot_started && $pdo->inTransaction()) {
 $pdo->commit();
 $snapshot_started = false;
 }

 safe_gzwrite($gz, "\nSET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n");
 if (!@gzclose($gz)) throw new Exception('Gzip dosyası kapatılırken hata oluştu.');
 $gz = null;

 if (!@rename($tmp_gz_file, $target_gz_file)) {
 throw new Exception('Geçici gzip dosyası asıl hedefe taşınamadı!');
 }
 $tmp_gz_file = '';

 // Finalizasyon: yalnızca dosya dosya doğrulama özeti + gzip bütünlüğü doğrulandıktan sonra tamamlanmış sayılır.
 verify_and_checksum_gzip($target_gz_file);
 $target_finalized = true;
 if ($apply_retention) {
 limit_backup_files($backup_dir, $config['max_backups']);
 }

 release_myisam_read_locks($myisam_lock_pdo);
 $myisam_lock_pdo = null;
 $update_progress('completed');
 return $target_gz_file;
 } catch (Throwable $e) {
 if ($snapshot_started) safe_transaction_rollback($pdo);
 if (is_resource($gz)) @gzclose($gz);
 release_myisam_read_locks($myisam_lock_pdo);
 $myisam_lock_pdo = null;

 if ($tmp_gz_file !== '' && is_file($tmp_gz_file)) @unlink($tmp_gz_file);
 if (!$target_finalized && $target_gz_file !== '' && is_file($target_gz_file)) {
 @unlink($target_gz_file);
 @unlink($target_gz_file . '.sha256');
 @unlink($target_gz_file . '.meta.json');
 }
 if ($progress_ready) $update_progress('failed', '', $e->getMessage());
 throw $e;
 } finally {
 if ($snapshot_started) safe_transaction_rollback($pdo);
 if (is_resource($gz)) @gzclose($gz);
 release_myisam_read_locks($myisam_lock_pdo);
 }
}

// =============================================================================
// PHP - YEDEK DOĞRULAMA VE SHA-256
// Oluşturulan .sql.gz dosyasını tekrar okuyarak sıkıştırılmış dosyanın bozuk olup
// olmadığını kontrol eder ve dosyanın SHA-256 özetini üretir.
// =============================================================================

function verify_and_checksum_gzip(string $file_path)
: string {
 if (!is_file($file_path)) throw new Exception("Yedek dosyası bulunamadı.");

 // Sağlama özeti sıkıştırılmış .gz bayt'ları üzerinden hesaplanır.
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

 if (!safe_file_put_contents($sha_path, $hash . " " . basename($file_path) . "\n", LOCK_EX)) {
 throw new Exception("SHA256 imza dosyası yazılamadı!");
 }

 return $hash;
}
function verify_backup_checksum(string $file_path)
: string {
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

 // 1) Ham .gz bayt'larının SHA256 değerini doğrula.
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
 // gzread() boş dönebilir; gzeof() sonraki döngüde EOF'yi ayarlar.
 }
 } finally {
 gzclose($gz);
 }

 return $current_hash;
}
/**
 * Geri yükleme sonrasında verilen tablo listesinde ANALYZE TABLE çalıştırır.
 * Mevcut bir PDO bağlantısı verilirse yeniden bağlantı açmadan ilerleme bilgisi döndürür.
 */
function analyze_tables_after_restore(
 string $db_name,
 array $config,
 array $tables,
 int $start_index = 0,
 int $max_tables = 0,
 ?PDO $existingPdo = null
)
: array {
 $result = [
 'processed' => 0,
 'successful' => 0,
 'failed' => 0,
 'next_index' => max(0, $start_index),
 'total' => count($tables),
 'warnings' => []
 ];

 if (!$tables) {
 $result['next_index'] = 0;
 return $result;
 }

 try {
 // ANALYZE TABLE ayrı bir bağlantıda çalıştırılır. Böylece geri yükleme işleminin
 // ana PDO bağlantısındaki işlem grubu/kilit durumuna dokunmaz.
 $analyzePdo = $existingPdo ?? get_pdo(
 (string)$config['db_host'],
 (string)$config['db_user'],
 (string)$config['db_pass'],
 $db_name,
 true,
 false
 );

 // Uzun üstveri/tablo kilidi beklemeleri geri yükleme işlemini kilitlemesin.
 try {
 $analyzePdo->exec("SET SESSION lock_wait_timeout = 5");
 } catch (Throwable $e) {
 Logger::warning('ANALYZE lock_wait_timeout ayarlanamadı: ' . $e->getMessage());
 }

 try {
 $analyzePdo->exec("SET SESSION innodb_lock_wait_timeout = 5");
 } catch (Throwable $e) {
 Logger::warning('ANALYZE innodb_lock_wait_timeout ayarlanamadı: ' . $e->getMessage());
 }

 $limit = $max_tables > 0
 ? min($max_tables, count($tables) - max(0, $start_index))
 : count($tables) - max(0, $start_index);

 $end = min(count($tables), max(0, $start_index) + max(0, $limit));

 for ($i = max(0, $start_index); $i < $end; $i++) {
 $table = (string)$tables[$i];

 if (!is_db_identifier_safe($table)) {
 $result['warnings'][] = "Geçersiz tablo adı nedeniyle ANALYZE atlandı: {$table}";
 $result['next_index'] = $i + 1;
 $result['processed']++;
 continue;
 }

 $q = '`' . str_replace('`', '``', $table) . '`';

 try {
 // ANALYZE ayrı PDO bağlantısında çalıştırılır.
 $stmt = $analyzePdo->query("ANALYZE NO_WRITE_TO_BINLOG TABLE {$q}");

 // Sonuç setini mutlaka tüket ve kapat.
 $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
 if ($stmt) $stmt->closeCursor();

 $tableHasError = false;
 foreach ($rows as $row) {
 $msgType = strtolower((string)($row['Msg_type'] ?? ''));
 $msgText = (string)($row['Msg_text'] ?? '');

 if ($msgType === 'error') {
 $tableHasError = true;
 $result['warnings'][] = sprintf(
 'ANALYZE [%s] hata: %s',
 $table,
 $msgText !== '' ? $msgText : 'Bilinmeyen hata'
 );
 } elseif ($msgType === 'warning') {
 $result['warnings'][] = sprintf(
 'ANALYZE [%s] uyarı: %s',
 $table,
 $msgText !== '' ? $msgText : 'Bilinmeyen uyarı'
 );
 }
 }

 if ($tableHasError) {
 $result['failed']++;
 } else {
 // PDO::sorgu başarılı ve ANALYZE sonucu ERROR içermiyorsa
 // bu tablo için ANALYZE gerçekten çalıştırılmış kabul edilir.
 $result['successful']++;
 }
 } catch (Throwable $e) {
 $result['failed']++;
 $result['warnings'][] = sprintf(
 'ANALYZE [%s] çalıştırılamadı: %s',
 $table,
 $e->getMessage()
 );
 }

 $result['processed']++;
 $result['next_index'] = $i + 1;
 }
 } catch (Throwable $e) {
 $result['warnings'][] = 'ANALYZE bağlantısı oluşturulamadı: ' . $e->getMessage();
 $result['failed'] += max(0, count($tables) - $result['processed']);
 $result['next_index'] = min(count($tables), max(0, $start_index) + $result['processed']);
 }

 return $result;
}

function verify_database_integrity_after_restore(PDO $pdo, string $db_name, bool $quick = true, bool $analyze = false)
: array {
 $report = [
 'status' => 'OK',
 'tables_checked' => 0,
 'fk_issues' => 0,
 'errors' => []
 ];
 try {
 $stmtTables = $pdo->query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = " . $pdo->quote($db_name) . " AND TABLE_TYPE = 'BASE TABLE' AND UPPER(COALESCE(ENGINE, '')) <> 'SEQUENCE' ORDER BY TABLE_NAME");
 $tables = $stmtTables ? $stmtTables->fetchAll(PDO::FETCH_COLUMN) : [];
 if ($stmtTables) $stmtTables->closeCursor();

 $report['tables_checked'] = count($tables);
 $check_sql = $quick ? "CHECK TABLE `%s` QUICK" : "CHECK TABLE `%s`";

 foreach ($tables as $t) {
 if (!is_db_identifier_safe($t)) continue;

 $chkStmt = $pdo->query(sprintf($check_sql, $t));
 if ($chkStmt) {
 $rows = $chkStmt->fetchAll(PDO::FETCH_ASSOC);
 $chkStmt->closeCursor();

 foreach ($rows as $row) {
 $msgType = strtolower($row['Msg_type'] ?? '');
 $msgText = strtolower($row['Msg_text'] ?? '');
 if ($msgType === 'error' || ($msgType === 'status' && $msgText !== 'ok' && $msgText !== 'table is already up to date')) {
 $report['errors'][] = "Tablo [$t]: " . (string)($row['Msg_text'] ?? 'Bilinmeyen CHECK TABLE sonucu');
 $report['status'] = 'WARNING';
 }
 }
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
 if (!is_db_identifier_safe($localTable) || !is_db_identifier_safe($remoteTable)) continue;
 usort($fk['columns'], static fn(array $x, array $y): int => $x['position'] <=> $y['position']);

 $join = [];
 $nonnull = [];
 $firstRemote = '';
 foreach ($fk['columns'] as $column) {
 $local = $column['local']; $remote = $column['remote'];
 if (!is_db_identifier_safe($local) || !is_db_identifier_safe($remote)) continue 2;
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
 * GERİ YÜKLEME ÖNCESİ veri tabanı TEMİZLEME
 * Geri yükleme işleminin ilk adımında bir kez çağrılır; sonraki adımlar bu temizliği tekrar etmez.
 */
/**
 * Geri yüklemeden önce hedef veri tabanındaki eski nesneleri temizler. Silme sırasını güvenli tutar ve hata olursa neyin silinemediğini bildirir.
 */
function clear_database_for_restore(PDO $pdo, string $db_name)
: array {
 $dropped = [];
 $failed = [];
 $counts = [
 'tables' => 0,
 'views' => 0,
 'triggers' => 0,
 'procedures' => 0,
 'functions' => 0,
 'routines' => 0,
 'events' => 0,
 'sequences' => 0,
 'total' => 0,
 ];

 try {
 $pdo->exec('SET FOREIGN_KEY_CHECKS=0');

 // Görünümleri tablolardan önce sil; ardından gerçek tabloları kaldır.
 $stmt = $pdo->prepare("SELECT TABLE_NAME, TABLE_TYPE, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY CASE WHEN TABLE_TYPE = 'VIEW' THEN 0 WHEN UPPER(COALESCE(ENGINE, '')) = 'SEQUENCE' THEN 1 ELSE 2 END, TABLE_NAME");
 $stmt->execute([$db_name]);
 $objects = $stmt->fetchAll(PDO::FETCH_ASSOC);
 $stmt->closeCursor();

 foreach ($objects as $object) {
 $name = (string)($object['TABLE_NAME'] ?? '');
 $type = strtoupper((string)($object['TABLE_TYPE'] ?? ''));
 $engine = strtoupper((string)($object['ENGINE'] ?? ''));
 if ($engine === 'SEQUENCE') {
 continue;
 }
 if ($name === '' || !is_db_identifier_safe($name)) {
 $failed[] = ['object' => $name, 'type' => $type, 'reason' => 'Geçersiz nesne adı'];
 continue;
 }

 $q = '`' . str_replace('`', '``', $name) . '`';
 try {
 $pdo->exec($type === 'VIEW' ? "DROP VIEW IF EXISTS {$q}" : "DROP TABLE IF EXISTS {$q}");
 $dropped[] = ['object' => $name, 'type' => $type];
 if ($type === 'VIEW') {
 $counts['views']++;
 } else {
 $counts['tables']++;
 }
 } catch (Throwable $e) {
 $failed[] = ['object' => $name, 'type' => $type, 'reason' => $e->getMessage()];
 }
 }

 // MariaDB SEQUENCE nesnelerini DROP SEQUENCE ile temizle.
 try {
 $stmt = $pdo->prepare("
 SELECT TABLE_NAME
 FROM information_schema.TABLES
 WHERE TABLE_SCHEMA = ?
 AND UPPER(COALESCE(ENGINE, '')) = 'SEQUENCE'
 ORDER BY TABLE_NAME
 ");
 $stmt->execute([$db_name]);
 $sequences = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($sequences as $name) {
 $name = (string)$name;
 if ($name === '' || !is_db_identifier_safe($name)) {
 $failed[] = ['object' => $name, 'type' => 'SEQUENCE', 'reason' => 'Geçersiz sequence adı'];
 continue;
 }
 $q = '`' . str_replace('`', '``', $name) . '`';
 try {
 $pdo->exec("DROP SEQUENCE IF EXISTS {$q}");
 $dropped[] = ['object' => $name, 'type' => 'SEQUENCE'];
 $counts['sequences']++;
 } catch (Throwable $e) {
 $failed[] = ['object' => $name, 'type' => 'SEQUENCE', 'reason' => $e->getMessage()];
 }
 }
 } catch (Throwable $e) {
 $failed[] = ['object' => '*', 'type' => 'SEQUENCE', 'reason' => $e->getMessage()];
 }

 // Trigger'lar tablolar silinse bile ayrıca kaldırılır.
 try {
 $stmt = $pdo->prepare("SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ?");
 $stmt->execute([$db_name]);
 $triggers = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($triggers as $name) {
 $name = (string)$name;
 if ($name === '' || !is_db_identifier_safe($name)) {
 $failed[] = ['object' => $name, 'type' => 'TRIGGER', 'reason' => 'Geçersiz trigger adı'];
 continue;
 }
 $q = '`' . str_replace('`', '``', $name) . '`';
 try {
 $pdo->exec("DROP TRIGGER IF EXISTS {$q}");
 $dropped[] = ['object' => $name, 'type' => 'TRIGGER'];
 $counts['triggers']++;
 } catch (Throwable $e) {
 $failed[] = ['object' => $name, 'type' => 'TRIGGER', 'reason' => $e->getMessage()];
 }
 }
 } catch (Throwable $e) {
 $failed[] = ['object' => '*', 'type' => 'TRIGGER', 'reason' => $e->getMessage()];
 }

 // Saklı yordam ve işlev nesnelerini kaldır.
 try {
 $stmt = $pdo->prepare("SELECT ROUTINE_NAME, ROUTINE_TYPE FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ?");
 $stmt->execute([$db_name]);
 $routines = $stmt->fetchAll(PDO::FETCH_ASSOC);
 $stmt->closeCursor();

 foreach ($routines as $routine) {
 $name = (string)($routine['ROUTINE_NAME'] ?? '');
 $type = strtoupper((string)($routine['ROUTINE_TYPE'] ?? ''));
 if ($name === '' || !is_db_identifier_safe($name)) {
 $failed[] = ['object' => $name, 'type' => $type ?: 'ROUTINE', 'reason' => 'Geçersiz routine adı'];
 continue;
 }

 $q = '`' . str_replace('`', '``', $name) . '`';
 try {
 if ($type === 'FUNCTION') {
 $pdo->exec("DROP FUNCTION IF EXISTS {$q}");
 $counts['functions']++;
 } elseif ($type === 'PROCEDURE') {
 $pdo->exec("DROP PROCEDURE IF EXISTS {$q}");
 $counts['procedures']++;
 } else {
 throw new Exception("Desteklenmeyen routine türü: {$type}");
 }
 $dropped[] = ['object' => $name, 'type' => $type];
 $counts['routines']++;
 } catch (Throwable $e) {
 $failed[] = ['object' => $name, 'type' => $type ?: 'ROUTINE', 'reason' => $e->getMessage()];
 }
 }
 } catch (Throwable $e) {
 $failed[] = ['object' => '*', 'type' => 'ROUTINE', 'reason' => $e->getMessage()];
 }

 // Olay Zamanlayıcısı nesnelerini kaldır.
 try {
 $stmt = $pdo->prepare("SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ?");
 $stmt->execute([$db_name]);
 $events = $stmt->fetchAll(PDO::FETCH_COLUMN);
 $stmt->closeCursor();

 foreach ($events as $name) {
 $name = (string)$name;
 if ($name === '' || !is_db_identifier_safe($name)) {
 $failed[] = ['object' => $name, 'type' => 'EVENT', 'reason' => 'Geçersiz event adı'];
 continue;
 }
 $q = '`' . str_replace('`', '``', $name) . '`';
 try {
 $pdo->exec("DROP EVENT IF EXISTS {$q}");
 $dropped[] = ['object' => $name, 'type' => 'EVENT'];
 $counts['events']++;
 } catch (Throwable $e) {
 $failed[] = ['object' => $name, 'type' => 'EVENT', 'reason' => $e->getMessage()];
 }
 }
 } catch (Throwable $e) {
 $failed[] = ['object' => '*', 'type' => 'EVENT', 'reason' => $e->getMessage()];
 }

 $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
 } catch (Throwable $e) {
 try { $pdo->exec('SET FOREIGN_KEY_CHECKS=1'); } catch (Throwable $ignored) {}
 throw $e;
 }

 $counts['total'] = count($dropped);

 if ($failed) {
 throw new Exception('Restore öncesi veritabanı tamamen temizlenemedi: ' . json_encode($failed, JSON_UNESCAPED_UNICODE));
 }

 Logger::warning(sprintf(
 'Restore öncesi veritabanı temizlendi: %s | tables=%d | views=%d | triggers=%d | procedures=%d | functions=%d | routines=%d | events=%d | total=%d',
 $db_name,
 $counts['tables'],
 $counts['views'],
 $counts['triggers'],
 $counts['procedures'],
 $counts['functions'],
 $counts['routines'],
 $counts['events'],
 $counts['total']
 ));

 return [
 'dropped' => $dropped,
 'failed' => $failed,
 'counts' => $counts,
 ];
}
function verify_restore_source_integrity(string $file_path)
: string {
 $hash = verify_backup_checksum($file_path);
 return strtolower($hash);
}

/**
 * GERİ YÜKLEMEDEN ÖNCE SON TEMİZLİK KONTROLÜ. Veri tabanının kendisi silinmez. Eski tablolar ve diğer nesneler kaldırılır ve sonra sayıları kontrol edilir.
 */
function verify_database_is_empty_for_restore(PDO $pdo, string $db_name)
: array {
 $counts = [
 'tables' => 0,
 'triggers' => 0,
 'routines' => 0,
 'events' => 0,
 'sequences' => 0,
 ];

 $checks = [
 'tables' => "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND UPPER(COALESCE(ENGINE, '')) <> 'SEQUENCE'",
 'triggers' => "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ?",
 'routines' => "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ?",
 'events' => "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ?",
 'sequences' => "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND UPPER(COALESCE(ENGINE, '')) = 'SEQUENCE'",
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
 'TABLES=%d, TRIGGERS=%d, ROUTINES=%d, EVENTS=%d, SEQUENCES=%d',
 $counts['tables'],
 $counts['triggers'],
 $counts['routines'],
 $counts['events'],
 $counts['sequences']
 )
 );
 }

 return $counts;
}

/**
 * Gzip dosyasındaki SQL’i parça parça okur. Tırnak, yorum ve DELIMITER bilgisini koruyarak tam SQL komutları oluşturur.
 */

// =============================================================================
// PHP - SQL GERİ YÜKLEME AYRIŞTIRICISI

/*
SQL DOSYASINI NASIL AYIRIYORUZ?
Bir .sql.gz dosyasında yüzlerce veya binlerce SQL komutu bulunabilir.
Ancak bir SQL komutunun içinde noktalı virgül de bulunabilir.

Bu nedenle basitçe:
 explode(';', $sql)
yapmak güvenilir değildir.

Ayrıştırıcı; tırnakların, yorumların ve DELIMITER değişikliklerinin
durumunu takip ederek gerçek komut sonlarını bulmaya çalışır.

Öğrenme noktası:
Metin ayrıştırırken yalnızca karakteri değil, karakterin bulunduğu
"durumu" da takip etmek gerekir.
*/

// Büyük SQL dosyasını tek seferde RAM'e almak yerine parça parça okur.
// Tırnak, yorum ve DELIMITER durumlarını takip ederek gerçek SQL komutlarını ayırır.
// =============================================================================

function restore_parse_buffer(
 string $buffer,
 string &$queryBuffer,
 bool &$inString,
 string &$stringChar,
 bool &$inCommentMulti,
 bool &$inCommentSingle,
 bool &$escaped,
 string &$currentDelimiter,
 string &$lineBuffer = '',
 string &$pendingBoundary = ''
)
: array {
 $extractedQueries = [];
 $bufLen = strlen($buffer);

 for ($i = 0; $i < $bufLen; $i++) {
 $char = $buffer[$i];
 $nextChar = ($i + 1 < $bufLen) ? $buffer[$i + 1] : '';

 if (strlen($queryBuffer) > VEDO_QUERY_BUFFER_MAX) {
 throw new Exception("Sorgu arabelleği çok büyüdü (50MB+). SQL dosyasını kontrol edin.");
 }

 // Bir parça sonunda kapanış tırnağı geldiğinde, sonraki parça'ın ilk
 // karakterinin ikinci aynı tırnak olup olmadığını henüz bilemeyiz. Bu
 // nedenle kapanışı bir sonraki karaktere kadar erteliyoruz.
 if ($pendingBoundary === 'string_quote') {
 $pendingBoundary = '';
 if ($inString && $char === $stringChar) {
 $queryBuffer .= $char;
 $lineBuffer .= $char;
 if (strlen($lineBuffer) > 4096) {
 $lineBuffer = substr($lineBuffer, -4096);
 }
 // İki ardışık aynı tırnak MySQL'de string/isim içindeki
 // kaçışlı tırnaktır. String açık kalır.
 continue;
 }

 // Önceki parça'ın sonundaki tırnak gerçek kapanışmış. Mevcut char
 // artık normal dış-string akışında işlenir.
 $inString = false;
 $stringChar = '';
 $escaped = false;
 }

 // Bir parça tam "--" ile bittiğinde üçüncü karakteri henüz bilmiyoruz.
 // MySQL'de -- yorumu yalnızca ardından boşluk/kontrol karakteri gelirse
 // başlar. Sonraki parça'ın ilk karakteri bunu kesinleştirir.
 if ($pendingBoundary === 'dash_comment') {
 $pendingBoundary = '';
 if (in_array($char, [' ', "\t", "\r", "\n"], true)) {
 $queryBuffer .= $char;
 $lineBuffer .= $char;
 if (strlen($lineBuffer) > 4096) {
 $lineBuffer = substr($lineBuffer, -4096);
 }
 $inCommentSingle = true;
 if ($char === "\n" || $char === "\r") {
 $lineBuffer = '';
 $inCommentSingle = false;
 }
 continue;
 }
 }

 // Satır arabelleği yalnızca mevcut fiziksel satırı taşır. String/yorum
 // içinde de newline geldiğinde sıfırlanması, parça sınırlarında yanlış
 // DELIMITER adayı oluşmasını engeller.
 $lineBuffer .= $char;
 if (strlen($lineBuffer) > 4096) {
 $lineBuffer = substr($lineBuffer, -4096);
 }

 if ($inCommentMulti) {
 $queryBuffer .= $char;

 // Kapanış "*/" parça sınırında bölündüyse, önceki char queryBuffer'daki
 // '*' olacaktır. Mevcut '/' geldiğinde yorumu kapat.
 if ($char === '/' && substr($queryBuffer, -2) === '*/') {
 $inCommentMulti = false;
 // Aynı parça içinde klasik "*/" kapanışı.
 } elseif ($char === '*' && $nextChar === '/') {
 $queryBuffer .= '/';
 $lineBuffer .= '/';
 if (strlen($lineBuffer) > 4096) {
 $lineBuffer = substr($lineBuffer, -4096);
 }
 $i++;
 $inCommentMulti = false;
 }

 if ($char === "\n" || $char === "\r") {
 $lineBuffer = '';
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
 if ($nextChar === '' && ($stringChar === "'" || $stringChar === '"' || $stringChar === '`')) {
 $pendingBoundary = 'string_quote';
 if ($char === "\n" || $char === "\r") {
 $lineBuffer = '';
 }
 continue;
 }

 // MySQL, tek ve çift tırnak ile backtick isim içinde iki
 // ardışık aynı karakteri kaçışlı tırnak olarak kabul edebilir.
 if (($stringChar === "'" || $stringChar === '"' || $stringChar === '`') && $nextChar === $stringChar) {
 $queryBuffer .= $nextChar;
 $lineBuffer .= $nextChar;
 if (strlen($lineBuffer) > 4096) {
 $lineBuffer = substr($lineBuffer, -4096);
 }
 $i++;
 continue;
 }
 $inString = false;
 $stringChar = '';
 }

 if ($char === "\n" || $char === "\r") {
 $lineBuffer = '';
 }
 continue;
 }

 // "/*" parça sınırında bölündüyse, mevcut '*' karakterinin hemen öncesi
 // queryBuffer'da '/' olduğundan yorumu burada başlat.
 if ($char === '*' && substr($queryBuffer, -1) === '/') {
 $queryBuffer .= $char;
 $inCommentMulti = true;
 continue;
 }

 if ($char === '/' && $nextChar === '*') {
 $queryBuffer .= '/*';
 $lineBuffer .= '*';
 if (strlen($lineBuffer) > 4096) {
 $lineBuffer = substr($lineBuffer, -4096);
 }
 $i++;
 $inCommentMulti = true;
 continue;
 }

 // "--" yalnızca ardından boşluk/kontrol karakteri varsa yorumdur.
 // İkinci '-' parça sınırında kalmışsa pendingBoundary ile sonraki parça'a
 // bırakılır. Böylece "1--2" gibi normal operatör dizileri bozulmaz.
 $isDashComment = false;
 if ($char === '-' && $nextChar === '-') {
 $afterDashPos = $i + 2;
 if ($afterDashPos < $bufLen && in_array($buffer[$afterDashPos], [' ', "\t", "\r", "\n"], true)) {
 $isDashComment = true;
 }
 }
 if (!$isDashComment && $char === '-' && substr($queryBuffer, -1) === '-') {
 if ($nextChar !== '' && in_array($nextChar, [' ', "\t", "\r", "\n"], true)) {
 $isDashComment = true;
 } elseif ($nextChar === '') {
 $pendingBoundary = 'dash_comment';
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

 // DELIMITER yalnızca satır tamamlandığında değerlendirilir.
 if ($char === "\n" || $char === "\r") {
 $line = trim($lineBuffer);
 if (preg_match('/^DELIMITER[ \t]+([^\s\r\n]+)$/i', $line, $matches)) {
 $newDelimiter = trim($matches[1]);
 if ($newDelimiter === '' || strlen($newDelimiter) > 32 || preg_match('/[\x00-\x1F\x7F]/', $newDelimiter)) {
 throw new Exception('Geçersiz DELIMITER yönergesi tespit edildi.');
 }
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

 // DELIMITER yönergesinin ilk satır parçası tamamlanmadan mevcut ayraç
 // ile SQL'i bölme. Bu kontrol yalnızca satır başındaki yönerge adayı için.
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
// Dosya sonunda kapanmamış string, yorum veya DELIMITER durumu varsa işlemi reddet.
function finalize_restore_parser(string &$queryBuffer, bool $inString, string $stringChar, bool $inCommentMulti, bool $inCommentSingle, bool $escaped, string $currentDelimiter, string $delimiterLineBuffer = '', string $pendingBoundary = '')
: ?string {
 // parça sonunda bekletilen tek tırnak EOF'da kaldıysa bu tırnak gerçek
 // kapanıştır; ikinci aynı tırnak gelecek bir sonraki parça bulunmamaktadır.
 if ($pendingBoundary === 'string_quote' && $inString) {
 $inString = false;
 $stringChar = '';
 $escaped = false;
 } elseif ($pendingBoundary !== '' && $pendingBoundary !== 'dash_comment') {
 throw new Exception('Restore parser bilinmeyen parça sınırı durumu ile sonlandı.');
 }

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

/**
 * SQL IMPORT GÜVENLİK KURALI
 *
 * Import dosyası çalıştırılabilir; ancak import başlamadan ÖNCE mevcut olan
 * hiçbir tablo, görünüm, sequence, tetikleyici, saklı yordam, işlev veya olay
 * değiştirilemez/silinemez.
 *
 * Import sırasında yeni oluşturulan tablolar üzerinde INSERT/UPDATE/DELETE/
 * REPLACE/ALTER/INDEX/TRUNCATE gibi işlemler yapılabilir. Yeni tabloların
 * gerektiğinde silinmesine de izin verilir. Olay/tetikleyici gibi sonradan otomatik
 * çalışarak mevcut veriye dokunabilecek nesneler import sırasında engellenir.
 */
function normalize_import_identifier_key(string $name)
: string {
 return vedo_utf8_lower($name);
}

/**
 * MySQL mysqldump uyumluluğu için version-conditional executable comment'leri
 * güvenlik analizinden önce normal SQL'e açar. Böylece MySQL'in version-conditional `SET` yorumları biçimindeki
 * standart dump satırları normal SET olarak doğrulanır. Açılan içerik daha sonra
 * mevcut allow-list tarafından ayrıca kontrol edilir; bu fonksiyon tek başına
 * hiçbir SQL komutuna izin vermez.
 */
/*
 * ADIM ADIM: MYSQL ÖZEL YORUMLARI
 * MySQL dump dosyalarında /*!40101 ... * / gibi sürüme bağlı
 * çalıştırılabilir yorumlar bulunabilir.
 *
 * 1) Yorumun özel MySQL formatında olup olmadığını tanır.
 * 2) Sürüm koşulunu dikkate alır.
 * 3) Çalıştırılması gereken SQL kısmını normal SQL metnine dönüştürür.
 * 4) Sonraki güvenlik doğrulamasının bu SQL'i görebilmesini sağlar.
 *
 * Neden? Standart mysqldump dosyalarının gereksiz yere reddedilmemesi,
 * fakat ortaya çıkan SQL'in yine güvenlik kontrolünden geçmesi için.
 */
function expand_mysql_executable_comments(string $sql)
: string {
 $len = strlen($sql);
 if ($len === 0) return $sql;
 $out = '';
 $inString = false;
 $stringChar = '';
 $escaped = false;

 for ($i = 0; $i < $len; $i++) {
 $char = $sql[$i];
 $next = ($i + 1 < $len) ? $sql[$i + 1] : '';

 if ($inString) {
 $out .= $char;
 if ($escaped) {
 $escaped = false;
 } elseif ($char === '\\') {
 $escaped = true;
 } elseif ($char === $stringChar) {
 if (($stringChar === "'" || $stringChar === '"' || $stringChar === '`') && $next === $stringChar) {
 $out .= $next;
 $i++;
 } else {
 $inString = false;
 $stringChar = '';
 }
 }
 continue;
 }

 if ($char === "'" || $char === '"' || $char === '`') {
 $inString = true;
 $stringChar = $char;
 $escaped = false;
 $out .= $char;
 continue;
 }

 if ($char === '/' && $next === '*' && ($i + 2 < $len) && $sql[$i + 2] === '!') {
 $end = strpos($sql, '*/', $i + 3);
 if ($end === false) {
 throw new Exception('SQL güvenlik analizi sırasında kapanmamış MySQL executable comment tespit edildi.');
 }
 $body = substr($sql, $i + 3, $end - ($i + 3));
 // MySQL syntax: /*!12345 SQL ... */ veya /*! SQL ... */.
 $body = preg_replace('/^\s*\d{0,6}\s*/', '', $body, 1) ?? $body;
 $out .= ' ' . $body . ' ';
 $i = $end + 1;
 continue;
 }

 $out .= $char;
 }

 return $out;
}

function strip_sql_comments_stateful(string $sql, bool $reject_executable_comments = false, bool $expand_executable_comments = false)
: string {
 $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql) ?? $sql;
 if ($expand_executable_comments) {
 $sql = expand_mysql_executable_comments($sql);
 }
 $len = strlen($sql);
 $out = '';
 $in_string = false;
 $string_char = '';
 $escaped = false;

 for ($i = 0; $i < $len; $i++) {
 $char = $sql[$i];
 $next = ($i + 1 < $len) ? $sql[$i + 1] : '';

 if ($in_string) {
 $out .= $char;
 if ($escaped) {
 $escaped = false;
 } elseif ($char === '\\') {
 $escaped = true;
 } elseif ($char === $string_char) {
 if (($string_char === "'" || $string_char === '"' || $string_char === '`') && $next === $string_char) {
 $out .= $next;
 $i++;
 continue;
 }
 $in_string = false;
 $string_char = '';
 }
 continue;
 }

 if ($char === "'" || $char === '"' || $char === '`') {
 $out .= $char;
 $in_string = true;
 $string_char = $char;
 $escaped = false;
 continue;
 }

 if ($char === '/' && $next === '*') {
 $is_executable = (($i + 2 < $len) && $sql[$i + 2] === '!');
 if ($is_executable && $reject_executable_comments) {
 throw new Exception('MySQL executable/conditional comment (/*!) import/restore sırasında yasaktır.');
 }

 $i += 2;
 $comment_closed = false;
 while ($i < $len) {
 if ($sql[$i] === '*' && (($i + 1) < $len) && $sql[$i + 1] === '/') {
 $i++;
 $comment_closed = true;
 break;
 }
 $i++;
 }
 if (!$comment_closed) {
 throw new Exception('SQL güvenlik analizi sırasında kapanmamış çok satırlı yorum tespit edildi.');
 }
 $out .= ' ';
 continue;
 }

 if ($char === '#') {
 $out .= ' ';
 while ($i + 1 < $len && $sql[$i + 1] !== "\n" && $sql[$i + 1] !== "\r") {
 $i++;
 }
 continue;
 }

 if ($char === '-' && $next === '-' && (($i + 2) >= $len || in_array($sql[$i + 2], [' ', "\t", "\r", "\n"], true))) {
 $out .= ' ';
 $i += 2;
 while ($i < $len && $sql[$i] !== "\n" && $sql[$i] !== "\r") {
 $i++;
 }
 $i--;
 continue;
 }

 $out .= $char;
 }

 if ($in_string) {
 throw new Exception('SQL güvenlik analizi sırasında kapanmamış string tespit edildi.');
 }

 return ltrim($out);
}

function import_strip_sql_comments_and_leading(string $sql)
: string {
 return strip_sql_comments_stateful($sql, false, true);
}

function parse_import_object_reference(string $reference, string $db_name)
: array {
 $reference = trim($reference);
 $pattern = '/^(?:(?:`([^`]+)`)|([\p{L}\p{N}_$]+))(?:\s*\.\s*(?:(?:`([^`]+)`)|([\p{L}\p{N}_$]+)))?$/u';
 if (!preg_match($pattern, $reference, $m)) {
 throw new Exception('SQL import nesne adı güvenli biçimde çözümlenemedi.');
 }

 $first = (string)(($m[1] ?? '') !== '' ? $m[1] : ($m[2] ?? ''));
 $second = (string)(($m[3] ?? '') !== '' ? $m[3] : ($m[4] ?? ''));
 $schema = $second === '' ? $db_name : $first;
 $name = $second === '' ? $first : $second;

 if (!is_db_identifier_safe($schema) || !is_db_identifier_safe($name)) {
 throw new Exception('SQL import içinde güvenli olmayan nesne adı tespit edildi.');
 }
 if (strcasecmp($schema, $db_name) !== 0) {
 throw new Exception("SQL import yalnızca hedef veritabanında ('{$db_name}') çalışabilir; '{$schema}' veritabanına erişim reddedildi.");
 }

 return [
 'schema' => $schema,
 'name' => $name,
 'key' => normalize_import_identifier_key($name),
 ];
}

function load_import_existing_schema(PDO $pdo, string $db_name)
: array {
 $objects = [
 'tables' => [],
 'views' => [],
 'sequences' => [],
 'functions' => [],
 'procedures' => [],
 'events' => [],
 'triggers' => [],
 ];

 $stmt = $pdo->prepare("SELECT TABLE_NAME, TABLE_TYPE, UPPER(COALESCE(ENGINE, '')) AS ENGINE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?");
 $stmt->execute([$db_name]);
 while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
 $name = (string)($row['TABLE_NAME'] ?? '');
 if ($name === '' || !is_db_identifier_safe($name)) continue;
 $key = normalize_import_identifier_key($name);
 $type = strtoupper((string)($row['TABLE_TYPE'] ?? ''));
 $engine = strtoupper((string)($row['ENGINE_NAME'] ?? ''));
 if ($type === 'VIEW') {
 $objects['views'][$key] = $name;
 } elseif ($engine === 'SEQUENCE') {
 $objects['sequences'][$key] = $name;
 } else {
 $objects['tables'][$key] = $name;
 }
 }
 $stmt->closeCursor();

 $stmt = $pdo->prepare("SELECT ROUTINE_NAME, ROUTINE_TYPE FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ?");
 $stmt->execute([$db_name]);
 while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
 $name = (string)($row['ROUTINE_NAME'] ?? '');
 if ($name === '' || !is_db_identifier_safe($name)) continue;
 $key = normalize_import_identifier_key($name);
 if (strtoupper((string)($row['ROUTINE_TYPE'] ?? '')) === 'FUNCTION') {
 $objects['functions'][$key] = $name;
 } else {
 $objects['procedures'][$key] = $name;
 }
 }
 $stmt->closeCursor();

 $stmt = $pdo->prepare("SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = ?");
 $stmt->execute([$db_name]);
 while ($name = $stmt->fetchColumn()) {
 $name = (string)$name;
 if ($name !== '' && is_db_identifier_safe($name)) {
 $objects['events'][normalize_import_identifier_key($name)] = $name;
 }
 }
 $stmt->closeCursor();

 $stmt = $pdo->prepare("SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = ?");
 $stmt->execute([$db_name]);
 while ($name = $stmt->fetchColumn()) {
 $name = (string)$name;
 if ($name !== '' && is_db_identifier_safe($name)) {
 $objects['triggers'][normalize_import_identifier_key($name)] = $name;
 }
 }
 $stmt->closeCursor();

 return $objects;
}

function import_target_was_existing(array $existing, string $type, string $name)
: bool {
 return isset($existing[$type][normalize_import_identifier_key($name)]);
}

function import_target_was_created(array $created, string $type, string $name)
: bool {
 return isset($created[$type][normalize_import_identifier_key($name)]);
}

function import_register_created(array &$created, string $type, string $name)
: void {
 $created[$type][normalize_import_identifier_key($name)] = $name;
}

function import_unregister_created(array &$created, string $type, string $name)
: void {
 unset($created[$type][normalize_import_identifier_key($name)]);
}

function import_policy_for_sql(string $sql, string $db_name, array $existing, array $created, bool $softMode = false)
: array {
 $clean = import_strip_sql_comments_and_leading($sql);
 if ($clean === '') {
 return ['allow' => true, 'class' => 'EMPTY'];
 }

 try {
 // Import de çalıştırılabilir SQL olduğu için geri yükleme ile aynı veri tabanı sınırını uygula.
 validate_restore_target_database($clean, $db_name, true);
 } catch (Throwable $targetError) {
 return ['allow' => false, 'reason' => $targetError->getMessage(), 'class' => 'TARGET_DATABASE'];
 }

 $forbidden = [
 // Bunlar veritabanı dışındaki sunucuya/hesaplara dokunabildiği için her iki modda da kapalıdır.
 '/^USE\s+/i',
 '/^(?:CREATE|ALTER|DROP)\s+DATABASE\b/i',
 '/^(?:CREATE|ALTER|DROP)\s+(?:USER|ROLE)\b/i',
 '/^(?:GRANT|REVOKE)\b/i',
 '/^CALL\b/i',
 '/^DO\b/i',
 '/^(?:LOAD\s+DATA|LOAD\s+XML)\b/i',
 '/^SELECT\b.*\bINTO\s+(?:OUTFILE|DUMPFILE)\b/is',
 '/^FLUSH\b/i',
 '/^KILL\b/i',
 '/^SHUTDOWN\b/i',
 '/^(?:INSTALL|UNINSTALL)\b/i',
 '/^RESET\b/i',
 ];
 if (!$softMode) {
 // Güvenli modda trigger ve event oluşturmak kapalıdır.
 $forbidden[] = '/^CREATE\s+TRIGGER\b/i';
 $forbidden[] = '/^CREATE\s+EVENT\b/i';
 }
 foreach ($forbidden as $pattern) {
 if (preg_match($pattern, $clean)) {
 return ['allow' => false, 'reason' => 'Bu SQL komutu import güvenlik politikası tarafından yasaklandı.', 'class' => 'FORBIDDEN'];
 }
 }

 if (preg_match('/^SET\s+/i', $clean)) {
 if (preg_match('/\b(?:GLOBAL|PERSIST|PERSIST_ONLY)\b/i', $clean)) {
 return ['allow' => false, 'reason' => 'GLOBAL/PERSIST kapsamlı SET komutları import sırasında yasaktır.', 'class' => 'SET'];
 }
 // mysqldump benzeri dosyalarda kullanılan geçici kullanıcı değişkenlerine
 // yalnızca sabit bir SESSION değişkenini kopyalayan güvenli formda izin ver.
 if (preg_match('/^\s*SET\s+@[A-Za-z0-9_$]+\s*=\s*@@(?:SESSION\.)?(?:CHARACTER_SET_CLIENT|CHARACTER_SET_RESULTS|CHARACTER_SET_CONNECTION|COLLATION_CONNECTION|SQL_MODE|TIME_ZONE|FOREIGN_KEY_CHECKS|UNIQUE_CHECKS|AUTOCOMMIT|SQL_LOG_BIN)\s*$/i', $clean)) {
 return ['allow' => true, 'class' => 'SET USER VARIABLE'];
 }
 // mysqldump benzeri dosyalarda kullanılan normal SESSION ayarlarına izin ver.
 if (preg_match('/^SET\s+NAMES\s+[A-Za-z0-9_]+(?:\s+COLLATE\s+[A-Za-z0-9_]+)?\s*$/i', $clean)) {
 return ['allow' => true, 'class' => 'SET'];
 }
 $allowed = [
 'FOREIGN_KEY_CHECKS', 'UNIQUE_CHECKS', 'SQL_MODE', 'TIME_ZONE',
 'CHARACTER_SET_CLIENT', 'CHARACTER_SET_RESULTS', 'CHARACTER_SET_CONNECTION', 'AUTOCOMMIT', 'SQL_LOG_BIN'
 ];
 foreach ($allowed as $variable) {
 if (preg_match('/^SET\s+(?:SESSION\s+|@@SESSION\.|@@LOCAL\.|@@)?' . preg_quote($variable, '/') . '\s*=/i', $clean)) {
 return ['allow' => true, 'class' => 'SET'];
 }
 }
 return ['allow' => false, 'reason' => 'İzin verilmeyen SET değişkeni.', 'class' => 'SET'];
 }

 if (preg_match('/^DROP\s+(?:TEMPORARY\s+)?TABLE(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' silinemez.", 'class' => 'DROP TABLE'];
 }
 return ['allow' => true, 'class' => 'DROP TABLE', 'object_type' => 'tables', 'object' => $ref['name']];
 }

 if (preg_match('/^CREATE\s+(?:TEMPORARY\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 $alreadyExists = import_target_was_existing($existing, 'tables', $ref['name']) || import_target_was_existing($existing, 'views', $ref['name']) || import_target_was_existing($existing, 'sequences', $ref['name']);
 $ifNotExists = preg_match('/\bIF\s+NOT\s+EXISTS\b/i', $clean) === 1;
 if ($alreadyExists && $softMode && $ifNotExists) {
 return ['allow' => true, 'class' => 'CREATE TABLE', 'object_type' => 'tables', 'object' => $ref['name']];
 }
 if (!$softMode && $alreadyExists) {
 return ['allow' => false, 'reason' => "Mevcut nesne '{$ref['name']}' üzerine CREATE TABLE uygulanamaz.", 'class' => 'CREATE TABLE'];
 }
 if (import_target_was_created($created, 'views', $ref['name']) || import_target_was_created($created, 'sequences', $ref['name'])) {
 return ['allow' => false, 'reason' => "Import sırasında oluşturulmuş farklı türdeki '{$ref['name']}' nesnesi üzerine tablo oluşturulamaz.", 'class' => 'CREATE TABLE'];
 }
 return ['allow' => true, 'class' => 'CREATE TABLE', 'object_type' => 'tables', 'object' => $ref['name']];
 }

 if ($softMode && preg_match('/^CREATE\s+OR\s+REPLACE\s+(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?(VIEW|FUNCTION|PROCEDURE|EVENT)\s+/i', $clean, $m)) {
 $kind = strtolower((string)$m[1]);
 $rest = preg_replace('/^CREATE\s+OR\s+REPLACE\s+/i', 'CREATE ', $clean, 1) ?? $clean;
 $patterns = [
 'view' => '/^CREATE\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'function' => '/^CREATE\s+FUNCTION\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'procedure' => '/^CREATE\s+PROCEDURE\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'event' => '/^CREATE\s+EVENT\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 ];
 if (isset($patterns[$kind]) && preg_match($patterns[$kind], $rest, $rm)) {
 $ref = parse_import_object_reference($rm[1], $db_name);
 $type = $kind === 'view' ? 'views' : ($kind === 'event' ? 'events' : $kind . 's');
 return ['allow' => true, 'class' => 'CREATE OR REPLACE', 'object_type' => $type, 'object' => $ref['name']];
 }
 }

 if ($softMode && preg_match('/^RENAME\s+TABLE\b/i', $clean)) {
 return ['allow' => true, 'class' => 'RENAME TABLE'];
 }

 if (preg_match('/^CREATE\s+(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?TRIGGER\s+((?:`[^`]+`|[\p{L}\p{N}_$]+))/iu', $clean, $m)) {
 if (!$softMode) {
 return ['allow' => false, 'reason' => 'CREATE TRIGGER yalnızca Yumuşak Import modunda kullanılabilir.', 'class' => 'CREATE TRIGGER'];
 }
 $ref = parse_import_object_reference($m[1], $db_name);
 if (import_target_was_existing($existing, 'triggers', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut trigger '{$ref['name']}' doğrudan değiştirilemez; önce DROP TRIGGER kullanılmalıdır.", 'class' => 'CREATE TRIGGER'];
 }
 if (import_target_was_created($created, 'triggers', $ref['name'])) {
 return ['allow' => false, 'reason' => "Import sırasında zaten oluşturulmuş trigger '{$ref['name']}' yeniden tanımlanamaz.", 'class' => 'CREATE TRIGGER'];
 }
 return ['allow' => true, 'class' => 'CREATE TRIGGER', 'object_type' => 'triggers', 'object' => $ref['name']];
 }

 $createObjectPatterns = [
 'views' => '/^CREATE\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'functions' => '/^CREATE\s+FUNCTION\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'procedures' => '/^CREATE\s+PROCEDURE\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'events' => '/^CREATE\s+EVENT\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'sequences' => '/^CREATE\s+SEQUENCE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 ];
 foreach ($createObjectPatterns as $type => $pattern) {
 if (preg_match($pattern, $clean, $m)) {
 if (preg_match('/^CREATE\s+(?:OR\s+REPLACE)\b/i', $clean)) {
 return ['allow' => false, 'reason' => 'CREATE OR REPLACE bu türde import sırasında desteklenmiyor; uygun script için DROP ardından CREATE kullanın.', 'class' => 'CREATE OR REPLACE'];
 }
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && import_target_was_existing($existing, $type, $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut {$type} nesnesi '{$ref['name']}' değiştirilemez.", 'class' => 'CREATE'];
 }
 if ($softMode && import_target_was_existing($existing, $type, $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut {$type} nesnesi '{$ref['name']}' önce DROP ile kaldırılmalıdır.", 'class' => 'CREATE'];
 }
 if (import_target_was_created($created, $type, $ref['name'])) {
 return ['allow' => false, 'reason' => "Import sırasında zaten oluşturulmuş '{$ref['name']}' nesnesi yeniden tanımlanamaz.", 'class' => 'CREATE'];
 }
 if (in_array($type, ['views', 'sequences'], true)) {
 if (import_target_was_existing($existing, 'tables', $ref['name']) || import_target_was_existing($existing, $type === 'views' ? 'sequences' : 'views', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut nesne '{$ref['name']}' üzerine yeni nesne oluşturulamaz.", 'class' => 'CREATE'];
 }
 }
 return ['allow' => true, 'class' => 'CREATE', 'object_type' => $type, 'object' => $ref['name']];
 }
 }

 if (preg_match('/^CREATE\s+(?:UNIQUE\s+)?(?:FULLTEXT\s+|SPATIAL\s+)?INDEX\s+(?:`[^`]+`|[\p{L}\p{N}_$]+)\s+ON\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' üzerinde index oluşturulamaz.", 'class' => 'CREATE INDEX'];
 }
 return ['allow' => true, 'class' => 'CREATE INDEX', 'object' => $ref['name']];
 }


 if (preg_match('/^ALTER\s+TABLE\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)\s+/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' ALTER TABLE ile değiştirilemez.", 'class' => 'ALTER TABLE'];
 }
 // Yumuşak modda ALTER TABLE serbesttir; yine de RENAME TABLE benzeri isim taşıma işlemlerini değil, yalnızca ALTER TABLE içini kabul ederiz.
 if (preg_match('/\bRENAME\s+(?:TO|AS)\b/i', $clean)) {
 return ['allow' => false, 'reason' => 'ALTER TABLE ... RENAME import güvenliği için yasaktır.', 'class' => 'ALTER TABLE'];
 }
 return ['allow' => true, 'class' => 'ALTER TABLE', 'object' => $ref['name']];
 }

 $dmlPatterns = [
 'INSERT' => '/^INSERT(?:\s+IGNORE)?\s+INTO\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'UPDATE' => '/^UPDATE\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)\s+/iu',
 'DELETE' => '/^DELETE\s+FROM\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'REPLACE' => '/^REPLACE(?:\s+INTO)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 ];
 foreach ($dmlPatterns as $verb => $pattern) {
 if (preg_match($pattern, $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' üzerinde {$verb} yapılamaz.", 'class' => $verb];
 }
 return ['allow' => true, 'class' => $verb, 'object' => $ref['name']];
 }
 }

 if (preg_match('/^TRUNCATE\s+(?:TABLE\s+)?((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' boşaltılamaz.", 'class' => 'TRUNCATE'];
 }
 return ['allow' => true, 'class' => 'TRUNCATE', 'object' => $ref['name']];
 }

 if (preg_match('/^DROP\s+INDEX(?:\s+IF\s+EXISTS)?\s+(?:`[^`]+`|[\p{L}\p{N}_$]+)\s+ON\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' üzerinde index silinemez.", 'class' => 'DROP INDEX'];
 }
 return ['allow' => true, 'class' => 'DROP INDEX', 'object' => $ref['name']];
 }

 $dropPatterns = [
 'views' => '/^DROP\s+VIEW(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'triggers' => '/^DROP\s+TRIGGER(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'functions' => '/^DROP\s+FUNCTION(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'procedures' => '/^DROP\s+PROCEDURE(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'events' => '/^DROP\s+EVENT(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 'sequences' => '/^DROP\s+SEQUENCE(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 ];
 foreach ($dropPatterns as $type => $pattern) {
 if (preg_match($pattern, $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, $type, $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut {$type} nesnesi '{$ref['name']}' silinemez.", 'class' => 'DROP'];
 }
 return ['allow' => true, 'class' => 'DROP', 'object_type' => $type, 'object' => $ref['name']];
 }
 }

 if (preg_match('/^(?:ANALYZE|OPTIMIZE|CHECK|REPAIR)\s+TABLE\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu', $clean, $m)) {
 $ref = parse_import_object_reference($m[1], $db_name);
 if (!$softMode && !import_target_was_created($created, 'tables', $ref['name'])) {
 return ['allow' => false, 'reason' => "Mevcut tablo '{$ref['name']}' üzerinde tablo bakım komutu çalıştırılamaz.", 'class' => 'TABLE MAINTENANCE'];
 }
 return ['allow' => true, 'class' => 'TABLE MAINTENANCE', 'object' => $ref['name']];
 }

 return ['allow' => false, 'reason' => 'SQL import güvenlik politikası bu komut türünü desteklemiyor.', 'class' => 'UNSUPPORTED'];
}

/**
 * SQL DOSYASI İÇERİ AKTARMA
 *
 * Güvenli mod mevcut nesneleri korur. Yumuşak mod veritabanı nesnelerine daha geniş
 * değişiklik izni verir; sunucu yönetimi komutları her iki modda da engellenir.
 */
/**
 * Yüklenen SQL’i önce kontrol eder. Güvenli bulunan aynı SQL daha sonra çalıştırılır.
 */
function cleanup_import_created_objects(PDO $pdo, array $created)
: void {
 try { $pdo->exec('SET FOREIGN_KEY_CHECKS=0'); } catch (Throwable $e) {}
 $dropOrder = [
 ['triggers', 'DROP TRIGGER IF EXISTS `'],
 ['events', 'DROP EVENT IF EXISTS `'],
 ['views', 'DROP VIEW IF EXISTS `'],
 ['procedures', 'DROP PROCEDURE IF EXISTS `'],
 ['functions', 'DROP FUNCTION IF EXISTS `'],
 ['sequences', 'DROP SEQUENCE IF EXISTS `'],
 ['tables', 'DROP TABLE IF EXISTS `'],
 ];
 foreach ($dropOrder as [$type, $prefix]) {
 foreach (($created[$type] ?? []) as $name) {
 $name = (string)$name;
 if ($name === '' || !is_db_identifier_safe($name)) continue;
 try { $pdo->exec($prefix . str_replace('`','``',$name) . '`'); }
 catch (Throwable $e) { Logger::warning("SQL IMPORT cleanup başarısız | type={$type} | object={$name} | error=" . $e->getMessage()); }
 }
 }
 try { $pdo->exec('SET FOREIGN_KEY_CHECKS=1'); } catch (Throwable $e) {}
}


/**
 * Soft import için DDL rollback'in implicit COMMIT davranışını aşmak amacıyla
 * import öncesi tam geçici snapshot oluşturur. Snapshot mysqlyedek altında tutulmaz.
 */
function create_soft_import_recovery_snapshot(PDO $pdo, string $db_name, array $config)
: array {
 $tempBase = rtrim((string)sys_get_temp_dir(), DIRECTORY_SEPARATOR);
 if ($tempBase === '') {
 throw new Exception('Soft import recovery için sistem geçici dizini bulunamadı.');
 }

 $snapshotDir = '';
 for ($attempt = 0; $attempt < 5; $attempt++) {
 $candidate = $tempBase . DIRECTORY_SEPARATOR . 'vedo_soft_import_' . bin2hex(random_bytes(12));
 if (@mkdir($candidate, 0700, true) && is_dir($candidate)) {
 $snapshotDir = $candidate;
 break;
 }
 }
 if ($snapshotDir === '') {
 throw new Exception('Soft import recovery için geçici snapshot klasörü oluşturulamadı.');
 }

 $lockHandle = null;
 try {
 $lockHandle = acquire_system_lock($snapshotDir, VEDO_DATABASE_OPERATION_LOCK, 0);
 if (!$lockHandle) {
 throw new Exception('Soft import recovery snapshot kilidi oluşturulamadı.');
 }

 $snapshotPath = perform_backup(
 $pdo,
 $db_name,
 $snapshotDir,
 $config,
 $lockHandle,
 null,
 '.vedo_soft_import_snapshot',
 false
 );
 $snapshotFile = basename($snapshotPath);
 if (!validate_backup_filename($snapshotFile)) {
 throw new Exception('Soft import recovery snapshot dosya adı doğrulanamadı.');
 }
 verify_backup_checksum($snapshotPath);

 Logger::warning(sprintf(
 'SOFT IMPORT RECOVERY SNAPSHOT HAZIR | db=%s | file=%s',
 $db_name,
 $snapshotFile
 ));

 return [
 'dir' => $snapshotDir,
 'file' => $snapshotFile,
 'path' => $snapshotPath,
 'lock' => $lockHandle,
 ];
 } catch (Throwable $e) {
 if (is_resource($lockHandle)) {
 release_system_lock($lockHandle);
 $lockHandle = null;
 }
 remove_soft_import_recovery_snapshot([
 'dir' => $snapshotDir,
 'file' => basename((string)($snapshotPath ?? '')),
 'path' => (string)($snapshotPath ?? ''),
 'lock' => null,
 ]);
 throw $e;
 }
}

function restore_soft_import_recovery_snapshot(PDO &$pdo, array $snapshot, string $db_name, array $config)
: void {
 $snapshotDir = (string)($snapshot['dir'] ?? '');
 $snapshotFile = (string)($snapshot['file'] ?? '');
 if ($snapshotDir === '' || $snapshotFile === '' || !is_dir($snapshotDir)) {
 throw new Exception('Soft import recovery snapshot yolu geçersiz veya kaybolmuş.');
 }
 if (!validate_backup_filename($snapshotFile)) {
 throw new Exception('Soft import recovery snapshot dosyası geçersiz.');
 }

 $snapshotPath = validate_path_safe($snapshotDir . DIRECTORY_SEPARATOR . $snapshotFile, $snapshotDir);
 if (!is_file($snapshotPath)) {
 throw new Exception('Soft import recovery snapshot dosyası bulunamadı.');
 }
 verify_backup_checksum($snapshotPath);

 $lockHandle = $snapshot['lock'] ?? null;
 $snapshot['lock'] = null;
 if (!is_resource($lockHandle)) {
 $lockHandle = acquire_system_lock($snapshotDir, VEDO_DATABASE_OPERATION_LOCK, 0);
 }
 if (!$lockHandle) {
 throw new Exception('Soft import recovery restore kilidi alınamadı.');
 }

 $recoveryConfig = $config;
 $recoveryConfig['analyze_after_restore'] = false;

 try {
 $recoveryJobId = bin2hex(random_bytes(16));
 perform_restore_cli_job(
 $pdo,
 $snapshotFile,
 $snapshotDir,
 $recoveryConfig,
 $lockHandle,
 $recoveryJobId,
 false
 );
 Logger::warning(sprintf(
 'SOFT IMPORT RECOVERY BAŞARILI | db=%s | snapshot=%s',
 $db_name,
 $snapshotFile
 ));
 } finally {
 release_system_lock($lockHandle);
 }
}

function remove_soft_import_recovery_snapshot(array &$snapshot)
: void {
 $lock = $snapshot['lock'] ?? null;
 if (is_resource($lock)) {
 release_system_lock($lock);
 }
 $snapshot['lock'] = null;

 $dir = (string)($snapshot['dir'] ?? '');
 $file = (string)($snapshot['file'] ?? '');
 $path = (string)($snapshot['path'] ?? '');

 if ($path !== '' && is_file($path)) @unlink($path);
 if ($path !== '' && is_file($path . '.sha256')) @unlink($path . '.sha256');
 if ($path !== '' && is_file($path . '.meta.json')) @unlink($path . '.meta.json');

 if ($dir !== '' && is_dir($dir)) {
 $children = array_merge(
 glob($dir . DIRECTORY_SEPARATOR . '*', GLOB_NOSORT) ?: [],
 glob($dir . DIRECTORY_SEPARATOR . '.*', GLOB_NOSORT) ?: []
 );
 foreach ($children as $child) {
 $base = basename($child);
 if ($base === '.' || $base === '..') continue;
 if (is_file($child) || is_link($child)) @unlink($child);
 }
 @rmdir($dir);
 }

 $snapshot = [];
}


// =============================================================================
// PHP - SQL DOSYASI İÇE AKTARMA

/*
GERİ YÜKLEMEDE GÜVENLİK
Kullanıcıdan gelen SQL dosyası doğrudan çalıştırılmamalıdır.

Programın yaklaşımı:
Dosya → SQL ayrıştırma → güvenlik kontrolü → izin verilen komutlar
→ MySQL üzerinde çalıştırma

Özellikle USE, kullanıcı/rol yönetimi, GRANT/REVOKE, OUTFILE gibi
yönetim veya dosya sistemi açısından tehlikeli olabilecek komutlar
kontrol edilir.

Buradaki amaç "SQL'i tamamen yasaklamak" değil, bu uygulamanın
göreviyle uyumlu SQL komutları dışındaki işlemleri engellemektir.
*/

// Bilgisayardan yüklenen SQL dosyasını güvenlik kurallarından geçirir, izin verilen
// komutları çalıştırır ve güvenli modda mevcut veri tabanı nesnelerini korur.
// =============================================================================

function import_uploaded_sql_file(PDO $pdo, array $uploadedFile, string $db_name, string $import_mode = 'safe', array &$recoveryReport = [])
: array {
 @set_time_limit(0);
 $import_mode = in_array($import_mode, ['safe', 'soft'], true) ? $import_mode : 'safe';
 $softMode = $import_mode === 'soft';
 @ignore_user_abort(true);

 $uploadError = (int)($uploadedFile['error'] ?? UPLOAD_ERR_NO_FILE);
 if ($uploadError !== UPLOAD_ERR_OK) {
 $messages = [
 UPLOAD_ERR_INI_SIZE => 'SQL dosyası sunucunun upload_max_filesize sınırını aşıyor.',
 UPLOAD_ERR_FORM_SIZE => 'SQL dosyası form tarafından izin verilen boyutu aşıyor.',
 UPLOAD_ERR_PARTIAL => 'SQL dosyası eksik yüklendi.',
 UPLOAD_ERR_NO_FILE => 'SQL dosyası seçilmedi.',
 UPLOAD_ERR_NO_TMP_DIR => 'Sunucuda geçici upload klasörü bulunamadı.',
 UPLOAD_ERR_CANT_WRITE => 'Yüklenen SQL dosyası geçici alana yazılamadı.',
 UPLOAD_ERR_EXTENSION => 'Bir PHP uzantısı SQL dosyası yüklemesini durdurdu.',
 ];
 throw new Exception($messages[$uploadError] ?? 'SQL dosyası yüklenemedi.');
 }

 $tmpPath = (string)($uploadedFile['tmp_name'] ?? '');
 $originalName = basename((string)($uploadedFile['name'] ?? 'sql-import.sql'));
 $fileSize = (int)($uploadedFile['size'] ?? 0);
 if ($tmpPath === '' || !is_uploaded_file($tmpPath) || !is_readable($tmpPath)) {
 throw new Exception('Yüklenen SQL dosyasının geçici kopyası okunamadı.');
 }

 $handle = @fopen($tmpPath, 'rb');
 if ($handle === false) {
 throw new Exception('Yüklenen SQL dosyası açılamadı.');
 }

 $existing = load_import_existing_schema($pdo, $db_name);
 $created = [
 'tables' => [], 'views' => [], 'sequences' => [], 'functions' => [],
 'procedures' => [], 'events' => [], 'triggers' => []
 ];

 $queryBuffer = '';
 $inString = false;
 $stringChar = '';
 $inCommentMulti = false;
 $inCommentSingle = false;
 $escaped = false;
 $currentDelimiter = ';';
 $delimiterLineBuffer = '';
 $pendingBoundary = '';
 $queryCount = 0;
 $successCount = 0;
 $errorCount = 0;
 $blockedCount = 0;
 $lineApprox = 1;
 $errors = [];
 $blocked = [];
 $startedAt = microtime(true);
 $ownTransaction = false;
 $softRecoverySnapshot = [];
 $softRecoveryNeeded = false;
 $softRecoveryError = null;

 $recordBlocked = static function (string $sql, string $reason, string $class) use (&$queryCount, &$blockedCount, &$blocked, &$lineApprox): void {
 $queryCount++;
 $blockedCount++;
 if (count($blocked) < 100) {
 $firstLine = preg_split('/\R/', $sql, 2)[0] ?? $sql;
 $firstLine = vedo_utf8_substr(trim($firstLine), 0, 500);
 $blocked[] = [
 'query' => $queryCount,
 'line' => $lineApprox,
 'sql' => $firstLine,
 'class' => $class,
 'reason' => $reason,
 ];
 }
 Logger::warning(sprintf(
 'SQL IMPORT GÜVENLİK ENGELİ | query=%d | line=%d | class=%s | reason=%s | sql=%s',
 $queryCount,
 $lineApprox,
 $class,
 $reason,
 summarize_sql_for_log($sql)
 ));
 };

 $executeQuery = static function (string $sql) use ($pdo, $db_name, $softMode, &$existing, &$created, &$queryCount, &$successCount, &$errorCount, &$errors, &$lineApprox, $recordBlocked): void {
 $sql = trim($sql);
 $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql) ?? $sql;
 if ($sql === '') return;

 try {
 // Güvenlik politikası ile çalıştırılan SQL birebir aynı normalize edilmiş metin olmalıdır.
 // Böylece yorum temizleme / parser farkı üzerinden güvenlik kuralını atlama mümkün olmaz.
 $sql_to_execute = import_strip_sql_comments_and_leading($sql);
 if ($sql_to_execute === '') {
 return;
 }
 $policy = import_policy_for_sql($sql_to_execute, $db_name, $existing, $created, $softMode);
 } catch (Throwable $e) {
 $recordBlocked($sql, $e->getMessage(), 'POLICY_ERROR');
 return;
 }

 if (!($policy['allow'] ?? false)) {
 if ($softMode) $softRecoveryNeeded = true;
 $recordBlocked($sql_to_execute, (string)($policy['reason'] ?? 'Güvenlik nedeniyle engellendi.'), (string)($policy['class'] ?? 'BLOCKED'));
 return;
 }

 $queryCount++;
 try {
 $pdo->exec($sql_to_execute);

 $successCount++;
 $class = (string)($policy['class'] ?? '');
 $type = (string)($policy['object_type'] ?? '');
 $object = (string)($policy['object'] ?? '');

 if ($class === 'CREATE TABLE' && $object !== '') {
 import_register_created($created, 'tables', $object);
 } elseif ($class === 'CREATE' && $type !== '' && $object !== '') {
 import_register_created($created, $type, $object);
 } elseif ($class === 'CREATE TRIGGER' && $object !== '') {
 import_register_created($created, 'triggers', $object);
 } elseif ($class === 'DROP TABLE' && $object !== '') {
 import_unregister_created($created, 'tables', $object);
 if ($softMode) unset($existing['tables'][normalize_import_identifier_key($object)]);
 } elseif ($class === 'DROP INDEX' && $object !== '') {
 // Index listesi ayrı tutulmadığından yalnızca komutun tabloya uygulanması kontrol edilir.
 } elseif ($class === 'DROP' && $type !== '' && $object !== '') {
 import_unregister_created($created, $type, $object);
 if ($softMode) unset($existing[$type][normalize_import_identifier_key($object)]);
 }
 } catch (Throwable $e) {
 $errorCount++;
 if ($softMode) $softRecoveryNeeded = true;
 if (count($errors) < 100) {
 $firstLine = preg_split('/\R/', $sql, 2)[0] ?? $sql;
 $firstLine = vedo_utf8_substr(trim($firstLine), 0, 500);
 $errors[] = [
 'query' => $queryCount,
 'line' => $lineApprox,
 'sql' => $firstLine,
 'error' => $e->getMessage()
 ];
 }
 Logger::error(sprintf(
 'SQL IMPORT SORGU HATASI | query=%d | line=%d | error=%s | sql=%s',
 $queryCount,
 $lineApprox,
 $e->getMessage(),
 summarize_sql_for_log($sql)
 ));
 }
 };

 try {
 if ($softMode) {
 $softRecoverySnapshot = create_soft_import_recovery_snapshot($pdo, $db_name, $config);
 }

 if (!$pdo->inTransaction()) {
 $pdo->beginTransaction();
 $ownTransaction = true;
 }
 $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
 $pdo->exec('SET UNIQUE_CHECKS=0');

 while (!feof($handle)) {
 $chunk = fread($handle, get_dynamic_restore_chunk_bytes());
 if ($chunk === false) {
 throw new Exception('SQL dosyası okunurken hata oluştu.');
 }
 if ($chunk === '') continue;

 $lineApprox += substr_count($chunk, "\n");
 $queries = restore_parse_buffer(
 $chunk,
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );
 foreach ($queries as $query) {
 $executeQuery($query);
 }
 }

 if ($delimiterLineBuffer !== '' && preg_match('/^\s*DELIMITER(?:[ \t]+[^\r\n]*)?$/i', $delimiterLineBuffer) && !$inString && !$inCommentMulti && !$inCommentSingle) {
 $queries = restore_parse_buffer(
 "\n",
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );
 foreach ($queries as $query) {
 $executeQuery($query);
 }
 }

 $finalQuery = finalize_restore_parser(
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );
 if ($finalQuery !== null) {
 $executeQuery($finalQuery);
 }
 } catch (Throwable $importError) {
 $softRecoveryNeeded = $softMode;
 if ($ownTransaction && $pdo->inTransaction()) {
 try { $pdo->rollBack(); } catch (Throwable $rollbackError) { Logger::error('SQL IMPORT rollback hatası: ' . $rollbackError->getMessage()); }
 }
 if (!$softMode) {
 cleanup_import_created_objects($pdo, $created);
 }
 $softRecoveryError = $importError;
 throw $importError;
 } finally {
 fclose($handle);

 if ($ownTransaction && $pdo->inTransaction()) {
 if (!$softRecoveryNeeded && $errorCount === 0 && $blockedCount === 0) {
 try { $pdo->commit(); } catch (Throwable $commitError) { Logger::error('SQL IMPORT commit hatası: ' . $commitError->getMessage()); throw $commitError; }
 } else {
 try { $pdo->rollBack(); } catch (Throwable $rollbackError) { Logger::error('SQL IMPORT rollback hatası: ' . $rollbackError->getMessage()); }
 if (!$softMode) cleanup_import_created_objects($pdo, $created);
 }
 }

 if ($softMode && !empty($softRecoverySnapshot) && ($softRecoveryNeeded || $softRecoveryError instanceof Throwable || $errorCount > 0 || $blockedCount > 0)) {
 try {
 Logger::warning(sprintf(
 'SOFT IMPORT ATOMİK RECOVERY BAŞLADI | db=%s | errors=%d | blocked=%d',
 $db_name,
 $errorCount,
 $blockedCount
 ));
 restore_soft_import_recovery_snapshot($pdo, $softRecoverySnapshot, $db_name, $config);
 $recoveryReport = [
 'status' => 'RECOVERED',
 'message' => 'Soft import sırasında hata veya engellenen sorgu oluştu; import öncesi veritabanı snapshot üzerinden geri yüklendi.',
 'errors' => $errorCount,
 'blocked' => $blockedCount
 ];
 Logger::warning('SOFT IMPORT ATOMİK RECOVERY TAMAMLANDI | db=' . $db_name);
 } catch (Throwable $recoveryError) {
 $recoveryReport = [
 'status' => 'RECOVERY_FAILED',
 'message' => 'Soft import başarısız oldu ve otomatik geri dönüş de tamamlanamadı.',
 'errors' => $errorCount,
 'blocked' => $blockedCount
 ];
 Logger::error(
 'SOFT IMPORT ATOMİK RECOVERY BAŞARISIZ | db=' . $db_name .
 ' | original_error=' . ($softRecoveryError instanceof Throwable ? $softRecoveryError->getMessage() : 'SQL/import validation error') .
 ' | recovery_error=' . $recoveryError->getMessage()
 );
 }
 }

 try {
 $pdo->exec('SET UNIQUE_CHECKS=1');
 $pdo->exec('SET FOREIGN_KEY_CHECKS=1');
 if (!$pdo->inTransaction()) {
 $pdo->exec('SET AUTOCOMMIT=1');
 }
 } catch (Throwable $e) {
 Logger::warning('SQL IMPORT sonrası session temizliği uygulanamadı: ' . $e->getMessage());
 }
 }

 $duration = round(microtime(true) - $startedAt, 2);
 if ($softMode && ($recoveryReport['status'] ?? '') === 'RECOVERY_FAILED') {
 throw new Exception('Soft import başarısız oldu ve eski veritabanına otomatik dönüş tamamlanamadı. Recovery snapshot geçici dizinde korunuyor; loglardaki SOFT IMPORT ATOMİK RECOVERY BAŞARISIZ kaydını kontrol edin.');
 }

 if ($softMode && !empty($softRecoverySnapshot)) {
 remove_soft_import_recovery_snapshot($softRecoverySnapshot);
 }

 Logger::info(sprintf(
 'SQL IMPORT TAMAMLANDI | mode=%s | db=%s | file=%s | bytes=%d | queries=%d | success=%d | errors=%d | blocked=%d | duration=%ss',
 $import_mode,
 $db_name,
 $originalName,
 $fileSize,
 $queryCount,
 $successCount,
 $errorCount,
 $blockedCount,
 $duration
 ));

 return [
 'file_name' => $originalName,
 'file_size' => $fileSize,
 'formatted_size' => format_bytes($fileSize),
 'queries' => $queryCount,
 'success' => $successCount,
 'errors' => $errorCount,
 'blocked' => $blockedCount,
 'duration_seconds' => $duration,
 'import_mode' => $import_mode,
 'error_details' => $errors,
 'blocked_details' => $blocked,
 'recovery' => $recoveryReport,
 ];
}

/**
 * Tek bir SQL komutunu güvenlik kurallarına göre kontrol eder. Sorun varsa hata verebilir veya başarısız olduğunu bildirir.
 */
function normalize_restore_identifier(string $identifier)
: string {
 $identifier = trim($identifier);
 if (strlen($identifier) >= 2 && $identifier[0] === '`' && $identifier[strlen($identifier) - 1] === '`') {
 $identifier = substr($identifier, 1, -1);
 $identifier = str_replace('``', '`', $identifier);
 }
 return $identifier;
}
function mask_restore_string_literals(string $sql)
: string {
 $len = strlen($sql);
 $out = '';
 $quote = '';
 $escaped = false;

 for ($i = 0; $i < $len; $i++) {
 $char = $sql[$i];
 $next = ($i + 1 < $len) ? $sql[$i + 1] : '';

 if ($quote !== '') {
 if ($escaped) {
 $escaped = false;
 $out .= ' ';
 continue;
 }
 if ($char === '\\') {
 $escaped = true;
 $out .= ' ';
 continue;
 }
 if (($quote === "'" || $quote === '"') && $char === $quote && $next === $quote) {
 $out .= ' ';
 $i++;
 continue;
 }
 if ($char === $quote) {
 $quote = '';
 }
 $out .= ($char === "\n" || $char === "\r") ? $char : ' ';
 continue;
 }

 if ($char === "'" || $char === '"') {
 $quote = $char;
 $escaped = false;
 $out .= ' ';
 continue;
 }
 $out .= $char;
 }

 if ($quote !== '') {
 throw new Exception('SQL güvenlik analizi sırasında kapanmamış string tespit edildi.');
 }
 return $out;
}
function validate_restore_target_database(string $sql, string $expectedDb, bool $throw = true)
: bool {
 $expectedDb = normalize_restore_identifier(trim($expectedDb));
 if ($expectedDb === '') return true;

 $clean = strip_sql_comments_stateful($sql, false, true);
 if ($clean === '') return true;
 $scan = mask_restore_string_literals($clean);
 $identifier = '(?:`(?:``|[^`])+`|[\\p{L}\\p{N}_$]+)';

 $contexts = [
 'FROM', 'JOIN', 'INTO', 'UPDATE', 'USING', 'VIEW', 'TABLE', 'TRIGGER', 'REFERENCES',
 'FUNCTION', 'PROCEDURE', 'EVENT', 'SEQUENCE'
 ];
 $contextPattern = '/\\b(?:' . implode('|', $contexts) . ')\\s+(?:IF\\s+(?:NOT\\s+)?EXISTS\\s+)?(' . $identifier . ')\\s*\\.\\s*' . $identifier . '/iu';

 $checkDb = static function (string $dbToken, string $source) use ($expectedDb, $throw): bool {
 $db = normalize_restore_identifier($dbToken);
 if (hash_equals($expectedDb, $db)) return true;
 if ($throw) {
 throw new Exception(
 'Güvenlik Engeli: Restore sorgusu hedef veritabanı dışına erişiyor: `' . $db . '`. Sorgu: ' .
 summarize_sql_for_log($source)
 );
 }
 return false;
 };

 if (preg_match_all($contextPattern, $scan, $matches, PREG_SET_ORDER)) {
 foreach ($matches as $match) {
 if (!$checkDb((string)$match[1], $clean)) return false;
 }
 }

 // CREATE TRIGGER ... ON db.table ve CREATE INDEX ... ON db.table biçimindeki
 // veri tabanı nitelemelerini kontrol et.
 if (preg_match('/^CREATE\\s+TRIGGER\\b.*?\\bON\\s+(' . $identifier . ')\\s*\\.\\s*' . $identifier . '/is', $scan, $m)) {
 if (!$checkDb((string)$m[1], $clean)) return false;
 }
 if (preg_match('/^CREATE\\s+(?:UNIQUE\\s+)?(?:FULLTEXT\\s+|SPATIAL\\s+)?INDEX\\b.*?\\bON\\s+(' . $identifier . ')\\s*\\.\\s*' . $identifier . '/is', $scan, $m)) {
 if (!$checkDb((string)$m[1], $clean)) return false;
 }

 if (preg_match('/^DROP\s+INDEX(?:\s+IF\s+EXISTS)?\s+(' . $identifier . ')\s+ON\s+(' . $identifier . ')\s*\.\s*' . $identifier . '/is', $scan, $m)) {
 if (!$checkDb((string)$m[2], $clean)) return false;
 }
 if (preg_match('/^CREATE\s+(?:TEMPORARY\s+)?TABLE\b.*?\bLIKE\s+(' . $identifier . ')\s*\.\s*' . $identifier . '/is', $scan, $m)) {
 if (!$checkDb((string)$m[1], $clean)) return false;
 }
 if (preg_match('/^ALTER\s+TABLE\b.*?\bRENAME\s+(?:TO|AS)\s+(' . $identifier . ')\s*\.\s*' . $identifier . '/is', $scan, $m)) {
 if (!$checkDb((string)$m[1], $clean)) return false;
 }

 // Çok tablolu UPDATE/DELETE ifadeleri virgüllerden sonra ek veri tabanı nitelemeleri içerebilir.
 if (preg_match('/^UPDATE\b.*?\bSET\b/is', $scan, $updatePrefix)) {
 if (preg_match_all('/,\s*(' . $identifier . ')\s*\.\s*' . $identifier . '/u', $updatePrefix[0], $extraMatches)) {
 foreach ($extraMatches[1] as $dbToken) {
 if (!$checkDb((string)$dbToken, $scan)) return false;
 }
 }
 }
 if (preg_match('/^DELETE\b.*?\bFROM\b.*?(?=\bWHERE\b|\bORDER\b|\bLIMIT\b|$)/is', $scan, $deletePrefix)) {
 if (preg_match_all('/,\s*(' . $identifier . ')\s*\.\s*' . $identifier . '/u', $deletePrefix[0], $extraMatches)) {
 foreach ($extraMatches[1] as $dbToken) {
 if (!$checkDb((string)$dbToken, $scan)) return false;
 }
 }
 }

 // RENAME TABLE may contain several tablo yapısı-qualified names; there are no column references
 // Bu ifadede kolon nitelemesi bulunmadığı için tüm nitelikli tanımlayıcıları taramak güvenlidir.
 if (preg_match('/^RENAME\\s+TABLE\\b/i', $scan) && preg_match_all('/(' . $identifier . ')\\s*\\.\\s*' . $identifier . '/u', $scan, $matches)) {
 foreach ($matches[1] as $dbToken) {
 if (!$checkDb((string)$dbToken, $clean)) return false;
 }
 }

 // FROM/JOIN/INTO kullanmayan veri tabanı nitelikli saklı yordam/işlev çağrılarını da yakala.
 // Örnek: CALL otherdb.proc() ve SELECT otherdb.fn(). Metin sabitleri daha önce maskelenmiştir.
 if (preg_match_all('/\bCALL\s+(' . $identifier . ')\s*\.\s*' . $identifier . '\b/iu', $scan, $callMatches)) {
 foreach ($callMatches[1] as $dbToken) {
 if (!$checkDb((string)$dbToken, $clean)) return false;
 }
 }
 if (preg_match_all('/(?<![\p{L}\p{N}_$`])(' . $identifier . ')\s*\.\s*' . $identifier . '\s*\(/u', $scan, $routineMatches)) {
 foreach ($routineMatches[1] as $dbToken) {
 if (!$checkDb((string)$dbToken, $clean)) return false;
 }
 }

 // db.table.column gibi üç parçalı başvurular ifadelerde ve saklı yordam gövdelerinde bulunabilir.
 if (preg_match_all('/(?<![\p{L}\p{N}_$`])(' . $identifier . ')\s*\.\s*' . $identifier . '\s*\.\s*' . $identifier . '/u', $scan, $tripleMatches)) {
 foreach ($tripleMatches[1] as $dbToken) {
 if (!$checkDb((string)$dbToken, $clean)) return false;
 }
 }
 return true;
}

function validate_restore_sql_statement(string $sql, bool $throw = true, string $expectedDb = '')
: bool {
 $allowed_sql_regexes = [
 '/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?TABLE\s+/i',
 '/^DROP\s+(?:TEMPORARY\s+)?TABLE(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+(?:(?:OR\s+REPLACE)\s+)?(?:(?:ALGORITHM\s*=\s*(?:UNDEFINED|MERGE|TEMPTABLE))\s+)?(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?(?:(?:SQL\s+SECURITY\s+(?:DEFINER|INVOKER))\s+)?VIEW\s+/i',
 '/^DROP\s+VIEW(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?TRIGGER\s+/i', '/^DROP\s+TRIGGER(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?FUNCTION\s+/i', '/^DROP\s+FUNCTION(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?PROCEDURE\s+/i', '/^DROP\s+PROCEDURE(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+(?:(?:DEFINER\s*=\s*(?:`[^`]+`@`[^`]+`|CURRENT_USER))\s+)?EVENT\s+/i', '/^DROP\s+EVENT(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+SEQUENCE\s+/i', '/^DROP\s+SEQUENCE(?:\s+IF\s+EXISTS)?\s+/i',
 '/^CREATE\s+(?:UNIQUE\s+)?(?:FULLTEXT\s+|SPATIAL\s+)?INDEX\s+/i', '/^DROP\s+INDEX(?:\s+IF\s+EXISTS)?\s+/i',
 '/^RENAME\s+TABLE\s+/i',
 '/^(?:INSERT(?:\s+IGNORE)?|UPDATE|DELETE|REPLACE)\s+/i', '/^TRUNCATE\s+(?:TABLE\s+)?/i',
 '/^ALTER\s+TABLE\s+/i', '/^(?:ANALYZE|OPTIMIZE|CHECK)\s+TABLE\s+/i',
 ];
 // Yalnızca bu yedek alma motorunun üretebileceği ve geri yükleme için gerekli SET değişkenleri kabul edilir.
 $allowed_set_variables = [
 'FOREIGN_KEY_CHECKS', 'UNIQUE_CHECKS', 'SQL_MODE', 'TIME_ZONE', 'NAMES',
 'CHARACTER_SET_CLIENT', 'CHARACTER_SET_RESULTS', 'CHARACTER_SET_CONNECTION',
 'AUTOCOMMIT', 'SQL_LOG_BIN'
 ];

 $sql_trimmed = (string)$sql;
 $sql_trimmed = preg_replace('/^\xEF\xBB\xBF/', '', $sql_trimmed) ?? $sql_trimmed;
 $clean_sql_check = strip_sql_comments_stateful($sql_trimmed, false, true);
 $clean_sql_check = preg_replace('/^(?:(?:\s+)|(?:\\[nrt])+)+/u', '', $clean_sql_check) ?? ltrim($clean_sql_check);
 $clean_sql_check = ltrim($clean_sql_check);
 if ($clean_sql_check === '') return true;

 $is_allowed = false;
 foreach ($allowed_sql_regexes as $pattern) {
 if (preg_match($pattern, $clean_sql_check)) { $is_allowed = true; break; }
 }
 if (!$is_allowed && str_starts_with(strtoupper($clean_sql_check), 'SET ')) {
 // Standart mysqldump dosyaları SET @OLD_...=@@... biçiminde geçici
 // kullanıcı değişkenleri kullanabilir. Yalnızca sabit bir session
 // değişkeninden değer alan bu zararsız form kabul edilir.
 if (preg_match('/^\s*SET\s+@[A-Za-z0-9_$]+\s*=\s*@@(?:SESSION\.)?(?:CHARACTER_SET_CLIENT|CHARACTER_SET_RESULTS|CHARACTER_SET_CONNECTION|COLLATION_CONNECTION|SQL_MODE|TIME_ZONE|FOREIGN_KEY_CHECKS|UNIQUE_CHECKS|AUTOCOMMIT|SQL_LOG_BIN)\s*$/i', $clean_sql_check)) {
 $is_allowed = true;
 }

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
 if ($is_allowed && $expectedDb !== '') {
 validate_restore_target_database($sql_trimmed, $expectedDb, $throw);
 }
 return $is_allowed;
}
function validate_backup_restore_compatibility(string $file_path, bool $verify_checksum = true, string $expectedDb = '')
: array {
 if ($verify_checksum) {
 verify_backup_checksum($file_path);
 }
 $gz = @gzopen($file_path, 'rb');
 if (!$gz) throw new Exception('Gzip arşivi test restore doğrulaması için açılamadı.');

 $query_buffer = ''; $in_string = false; $string_char = ''; $in_comment_multi = false;
 $in_comment_single = false; $escaped = false; $current_delimiter = ';'; $delimiter_line_buffer = ''; $query_count = 0; $pending_boundary = '';
 try {
 while (!gzeof($gz)) {
 $chunk = gzread($gz, get_dynamic_restore_chunk_bytes());
 if ($chunk === false) throw new Exception('Gzip test restore doğrulaması okunurken hata oluştu.');
 if ($chunk === '') continue;
 $queries = restore_parse_buffer($chunk, $query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer, $pending_boundary);
 foreach ($queries as $query) {
 validate_restore_sql_statement($query, true, $expectedDb);
 $query_count++;
 }
 }
 if ($delimiter_line_buffer !== '' && preg_match('/^\s*DELIMITER(?:[ \t]+[^\r\n]*)?$/i', $delimiter_line_buffer) && !$in_string && !$in_comment_multi && !$in_comment_single) {
 $queries = restore_parse_buffer("\n", $query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer, $pending_boundary);
 foreach ($queries as $query) {
 validate_restore_sql_statement($query, true, $expectedDb);
 $query_count++;
 }
 }
 $final_query = finalize_restore_parser($query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer, $pending_boundary);
 if ($final_query !== null) {
 validate_restore_sql_statement($final_query, true, $expectedDb);
 $query_count++;
 }
 } finally {
 gzclose($gz);
 }
 return ['status'=>'OK', 'queries_validated'=>$query_count];
}
function extract_restore_table_name(string $sql)
: string {
 $sql = trim($sql);
 $sql = preg_replace('/^\xEF\xBB\xBF/', '', $sql) ?? $sql;
 $identifier = '(?:`[^`]+`|[\p{L}\p{N}_$]+)';
 $qualified = $identifier . '(?:\s*\.\s*' . $identifier . ')?';
 $patterns = [
 '/^INSERT(?:\s+IGNORE)?\s+INTO\s+(' . $qualified . ')/iu',
 '/^REPLACE(?:\s+INTO)?\s+(' . $qualified . ')/iu',
 '/^UPDATE\s+(' . $qualified . ')/iu',
 '/^DELETE\s+FROM\s+(' . $qualified . ')/iu',
 '/^(?:CREATE|DROP|ALTER)\s+(?:TEMPORARY\s+)?(?:TABLE|VIEW|TRIGGER|FUNCTION|PROCEDURE|EVENT|SEQUENCE)(?:\s+IF\s+(?:NOT\s+)?EXISTS)?\s+(' . $qualified . ')/iu',
 '/^TRUNCATE\s+(?:TABLE\s+)?(' . $qualified . ')/iu'
 ];
 foreach ($patterns as $pattern) {
 if (preg_match($pattern, $sql, $m)) {
 $object=trim((string)$m[1]);
 if(str_contains($object,'.')){$parts=preg_split('/\s*\.\s*/u',$object);$object=(string)end($parts);}
 return preg_replace('/^`([^`]*)`$/u','$1',$object) ?? $object;
 }
 }
 return '';
}
/**
 * Restore sırasında transient lock/deadlock retry yapılmadan önce mevcut SESSION durumunu saklar.
 * Yeni PDO açıldığında aynı davranışın devam etmesi için uygulanabilir değişkenleri yeniden kurar.
 */
function capture_restore_session_state(PDO $pdo)
: array {
 try {
 $stmt = $pdo->query("SELECT
 @@SESSION.sql_mode AS sql_mode,
 @@SESSION.time_zone AS time_zone,
 @@SESSION.character_set_client AS character_set_client,
 @@SESSION.character_set_results AS character_set_results,
 @@SESSION.character_set_connection AS character_set_connection,
 @@SESSION.collation_connection AS collation_connection,
 @@SESSION.foreign_key_checks AS foreign_key_checks,
 @@SESSION.unique_checks AS unique_checks,
 @@SESSION.autocommit AS autocommit");
 $row = $stmt ? $stmt->fetch(PDO::FETCH_ASSOC) : false;
 if (!is_array($row)) return [];
 return $row;
 } catch (Throwable $e) {
 Logger::warning('Restore SESSION durumu okunamadı; reconnect sonrası temel ayarlar korunacak: ' . $e->getMessage());
 return [];
 }
}

function apply_restore_session_state(PDO $pdo, array $state)
: void {
 $quote = static function (PDO $connection, mixed $value): string {
 return $connection->quote((string)$value);
 };

 $setters = [
 'sql_mode' => 'SET SESSION sql_mode = %s',
 'time_zone' => 'SET SESSION time_zone = %s',
 'character_set_client' => 'SET SESSION character_set_client = %s',
 'character_set_results' => 'SET SESSION character_set_results = %s',
 'character_set_connection' => 'SET SESSION character_set_connection = %s',
 'collation_connection' => 'SET SESSION collation_connection = %s',
 'foreign_key_checks' => 'SET SESSION foreign_key_checks = %d',
 'unique_checks' => 'SET SESSION unique_checks = %d',
 'autocommit' => 'SET SESSION autocommit = %d',
 ];

 foreach ($setters as $key => $template) {
 if (!array_key_exists($key, $state) || $state[$key] === null || $state[$key] === '') continue;
 $value = $state[$key];
 if (in_array($key, ['foreign_key_checks', 'unique_checks', 'autocommit'], true)) {
 $pdo->exec(sprintf($template, (int)$value));
 } else {
 $pdo->exec(sprintf($template, $quote($pdo, $value)));
 }
 }
}

/**
 * SQL komutlarını sırayla çalıştırır ve ilerlemeyi günceller. Her komuttan önce güvenlik kontrolü yapılır.
 */
function restore_execute_sql(PDO &$pdo, array $queries, int &$processed_tables_count, int &$processed_rows_count, string $backup_dir, array $config = [], ?string &$current_table = null)
: int {
 $executed = 0;
 $max_retries = 5;

 foreach ($queries as $sql) {
 $sql_trimmed = (string)$sql;
 $detected_table = extract_restore_table_name($sql_trimmed);
 if ($detected_table !== '' && $current_table !== null) {
 if ((string)$current_table !== $detected_table) {
 Logger::info(sprintf('RESTORE TABLO İŞLENİYOR | table=%s', $detected_table));
 }
 $current_table = $detected_table;
 }
 $sql_trimmed = preg_replace('/^\xEF\xBB\xBF/', '', $sql_trimmed) ?? $sql_trimmed;
 $sql_trimmed = preg_replace('/^(?:(?:\s+)|(?:\\[nrt])+)+/u', '', $sql_trimmed) ?? ltrim($sql_trimmed);
 $sql_to_execute = $sql_trimmed;
 validate_restore_sql_statement($sql_to_execute, true, (string)($config['db_name'] ?? ''));

 $attempt = 0;
 $success = false;
 $last_error_message = '';

 while ($attempt < $max_retries && !$success) {
 $attempt++;
 try {
 $pdo->exec($sql_to_execute);
 $success = true;
 } catch (Exception $e) {
 $last_error_message = $e->getMessage();
 $error_code = (int)$e->getCode();

 // 2006/2013 (bağlantı koptu/kayboldu) hataları bilerek yeniden denenmez. Sunucu,
 // istemci bağlantı hatasını görmeden önce sorguyu çalıştırmış olabilir; yeniden çalıştırmak
 // veri değiştiren SQL işlemlerini iki kez uygulayabilir. Bu hataları geri yükleme kurtarma mekanizmasına bırak.
 $transient_codes = [1205, 1213, 40001];
 $is_transient = in_array($error_code, $transient_codes, true) ||
 stripos($last_error_message, 'deadlock') !== false ||
 stripos($last_error_message, 'lock wait timeout') !== false ||
 // Bağlantı kopması hatalarını tekrar denenecek hata olarak kabul etme.
 false;

 if ($is_transient) {
 if ($pdo->inTransaction()) {
 // Aktif parça işlem grubu'ı sırasında PDO bağlantısını değiştirmek işlem grubu durumunu kaybettirir.
 // Aktif işlem grubu varken bağlantıyı değiştirmek güvenli olmadığından yeniden deneme yapılmaz.
 break;
 }
 if (!empty($config)) {
 try {
 $sessionState = capture_restore_session_state($pdo);
 $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], true, $config['use_persistent_pdo'] ?? false);
 if (!empty($sessionState)) {
 apply_restore_session_state($pdo, $sessionState);
 }
 // Restore işlemi transient lock hatası sonrası devam ediyorsa güvenli kontrol ayarlarını kapalı tut.
 $pdo->exec("SET SESSION FOREIGN_KEY_CHECKS=0");
 $pdo->exec("SET SESSION UNIQUE_CHECKS=0");
 } catch (Exception $reEx) {
 Logger::warning("Yeniden PDO bağlantı kurulum/session restore hatası: " . $reEx->getMessage());
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
 Logger::error("SQL Hatası (Deneme {$attempt}): {$last_error_message} | Sorgu: " . summarize_sql_for_log($sql_to_execute));
 throw new Exception("SQL Çalıştırma Hatası: " . $last_error_message);
 }

 $executed++;
 restore_calculate_progress($sql, $processed_tables_count, $processed_rows_count);
 }
 return $executed;
}
function summarize_sql_for_log(string $sql)
: string {
 $sql = trim($sql);
 if ($sql === '') {
 return 'EMPTY';
 }

 $sql = strip_sql_comments_stateful($sql, false);
 $sql = trim((string)(preg_replace('/\s+/u', ' ', $sql) ?? $sql));

 $type = strtoupper((string)(preg_match('/^([A-Z]+)/iu', $sql, $m) ? $m[1] : 'SQL'));
 $object = '';

 $patterns = [
 '/^INSERT(?:\s+IGNORE)?\s+INTO\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 '/^(?:UPDATE|DELETE\s+FROM|REPLACE(?:\s+INTO)?)\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu',
 '/^(?:CREATE|DROP|ALTER)\s+(?:TEMPORARY\s+)?(?:TABLE|VIEW|TRIGGER|FUNCTION|PROCEDURE|EVENT|SEQUENCE)(?:\s+IF\s+EXISTS)?\s+((?:`[^`]+`|[\p{L}\p{N}_$]+)(?:\s*\.\s*(?:`[^`]+`|[\p{L}\p{N}_$]+))?)/iu'
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

function restore_calculate_progress(string $sql, int &$processed_tables_count, int &$processed_rows_count)
: void {
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
 str_starts_with($upper_prefix, 'CREATE EVENT') ||
 str_starts_with($upper_prefix, 'CREATE SEQUENCE') ||
 str_starts_with($upper_prefix, 'DROP SEQUENCE')
 ) {
 $processed_tables_count++;
 }
 }
}

// 6A. ARKA PLAN CLI İŞLERİ

/*
CLI işçi süreç NEDİR?
CLI (Command Line Interface), PHP'nin tarayıcı isteği olmadan
komut satırında çalışan şeklidir.

Örneğin panel uzun bir yedekleme başlatmak istediğinde:
Tarayıcı → PHP → ayrı PHP CLI süreci → uzun işlem

Tarayıcı bu uzun işlemi kendisi taşımak yerine durum bilgisini
izleyebilir.

CLI'nin önemli avantajı:
Uzun işlem doğrudan HTTP isteğinin yaşam süresine bağlı değildir.
Bu nedenle tarayıcının kapanması veya HTTP isteğinin bitmesi,
CLI işinin normal şartlarda aynı şekilde sürmesine engel olmaz.

Bu uygulamada CLI kullanılabiliyorsa uzun süren işler için
CLI tercih edilmesinin ana nedeni budur.
*/

// Panelden başlatılan uzun yedek alma/geri yükleme işlemleri ayrı bir komut satırı PHP sürecinde çalıştırılır.
// Tarayıcı yalnızca iş durumunu izler; uzun işlem doğrudan HTTP isteğine bağlı değildir.
function write_cli_job_state(string $backup_dir, string $job_id, array $state)
: void {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 throw new Exception('Geçersiz CLI job ID.');
 }

 $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
 $tmp = $path . '.tmp';
 $lockPath = $path . '.state.lock';

 // Timing ek bilgi is immutable for the lifetime of a job. Some progress
 // callbacks build a compact state array and would otherwise accidentally
 // drop job_started_at, which makes the arayüz elapsed counter reset to zero.
 // Inherit the existing start time whenever the caller does not provide it.
 if (!isset($state['job_started_at']) || !is_numeric($state['job_started_at']) || (float)$state['job_started_at'] <= 0) {
 $existingRaw = @file_get_contents($path);
 $existingState = is_string($existingRaw) ? json_decode($existingRaw, true) : null;
 $existingStartedAt = is_array($existingState) ? ($existingState['job_started_at'] ?? null) : null;
 if (is_numeric($existingStartedAt) && (float)$existingStartedAt > 0) {
 $state['job_started_at'] = (float)$existingStartedAt;
 }
 }

 $state['job_id'] = $job_id;
 $nowMicro = microtime(true);
 if (isset($state['job_started_at']) && is_numeric($state['job_started_at']) && (float)$state['job_started_at'] > 0) {
 $startMicro = (float)$state['job_started_at'];
 $calculatedElapsed = max(0.0, $nowMicro - $startMicro);
 // Completed jobs keep their authoritative recorded duration.
 if (($state['status'] ?? '') === 'completed' && isset($state['duration_seconds']) && is_numeric($state['duration_seconds'])) {
 $calculatedElapsed = max(0.0, (float)$state['duration_seconds']);
 }
 $state['elapsed_seconds'] = round($calculatedElapsed, 2);
 }
 $state['updated_at'] = time();
 $json = json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

 $lockFp = @fopen($lockPath, 'c+');
 if ($lockFp === false) {
 throw new Exception('CLI job durum kilidi oluşturulamadı.');
 }

 try {
 if (!@flock($lockFp, LOCK_EX)) {
 throw new Exception('CLI job durum kilidi alınamadı.');
 }

 if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
 @unlink($tmp);
 throw new Exception('CLI job durum dosyası yazılamadı.');
 }

 @flock($lockFp, LOCK_UN);
 } finally {
 if (is_resource($lockFp)) {
 @flock($lockFp, LOCK_UN);
 @fclose($lockFp);
 }
 }
}
function update_cli_job_state_for_prepare_worker(
 string $backup_dir,
 string $job_id,
 string $workerToken,
 callable $mutator
)
: bool {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id) || !preg_match('/^[a-f0-9]{32}$/', $workerToken)) {
 return false;
 }

 $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
 $tmp = $path . '.tmp';
 $lockPath = $path . '.state.lock';
 $lockFp = @fopen($lockPath, 'c+');
 if ($lockFp === false) return false;

 try {
 if (!@flock($lockFp, LOCK_EX)) return false;
 $raw = @file_get_contents($path);
 $current = is_string($raw) ? json_decode($raw, true) : null;
 if (!is_array($current)
 || ($current['engine'] ?? '') !== 'web'
 || ($current['type'] ?? '') !== 'restore'
 || ($current['phase'] ?? '') !== 'prepare_stream'
 || !empty($current['recovery_mode'])
 || !hash_equals($workerToken, (string)($current['prepare_stream_worker_token'] ?? ''))
 ) {
 return false;
 }

 $prepareStatus = (string)($current['prepare_stream_status'] ?? '');
 if (in_array($prepareStatus, ['completed', 'failed'], true)) {
 return false;
 }

 $updated = $mutator($current);
 if (!is_array($updated)) return false;
 $updated['job_id'] = $job_id;
 $updated['updated_at'] = time();
 $json = json_encode($updated, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
 if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
 @unlink($tmp);
 return false;
 }
 return true;
 } catch (Throwable $e) {
 Logger::warning('Prepare-stream optimistic state güncellenemedi: ' . $e->getMessage());
 @unlink($tmp);
 return false;
 } finally {
 @flock($lockFp, LOCK_UN);
 @fclose($lockFp);
 }
}

function reserve_cli_job_state(
 string $backup_dir,
 string $job_id,
 string $type,
 string $file = ''
)
: void {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 throw new Exception('Geçersiz CLI job ID.');
 }
 if (!in_array($type, ['backup', 'restore', 'integrity'], true)) {
 throw new Exception('Geçersiz CLI job tipi.');
 }

 $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
 $fp = @fopen($path, 'x');
 if ($fp === false) {
 throw new Exception('CLI job state rezervasyonu zaten mevcut.');
 }

 try {
 $state = [
 'job_id' => $job_id,
 'type' => $type,
 'engine' => 'cli',
 'status' => 'starting',
 'phase' => 'starting',
 'percent' => 0,
 'file' => $file,
 'job_reserved_at' => time(),
 'job_started_at' => microtime(true),
 'message' => 'CLI Worker başlatılması için job ayrıldı.'
 ];
 $json = json_encode(
 $state,
 JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
 );
 $offset = 0;
 $length = strlen($json);
 while ($offset < $length) {
 $written = @fwrite($fp, substr($json, $offset));
 if ($written === false || $written === 0) {
 throw new Exception('CLI job state rezervasyonu yazılamadı.');
 }
 $offset += $written;
 }
 if (!@fflush($fp)) {
 throw new Exception('CLI job state rezervasyonu diske aktarılamadı.');
 }
 } catch (Throwable $e) {
 @fclose($fp);
 @unlink($path);
 throw $e;
 }

 @fclose($fp);
}

function read_cli_job_state(string $backup_dir, string $job_id)
: array {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) return [];
 $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
 if (!is_file($path)) return [];
 $data = json_decode((string)@file_get_contents($path), true);
 return is_array($data) ? $data : [];
}
function is_recoverable_web_restore_state(array $state)
: bool {
 return ($state['engine'] ?? '') === 'web'
 && ($state['type'] ?? '') === 'restore'
 && empty($state['restore_verified'])
 && in_array((string)($state['phase'] ?? ''), ['emergency_backup', 'clear_database', 'prepare_stream', 'preflight_stream', 'restore'], true)
 && !empty($state['emergency_backup_completed'])
 && !empty($state['emergency_file']);
}

function is_nonterminal_restore_state_protected(array $state)
: bool {
 if (($state['type'] ?? '') !== 'restore') return false;
 if (!empty($state['recovery_required'])) return true;
 if (!empty($state['recovery_mode']) && ($state['status'] ?? '') !== 'completed') return true;
 if (in_array((string)($state['phase'] ?? ''), ['analyze', 'analyze_pending'], true)) return true;
 return in_array((string)($state['phase'] ?? ''), [
 'starting', 'verify_source', 'check_database', 'emergency_backup',
 'clear_database', 'preflight_stream', 'restore'
 ], true) && ($state['status'] ?? '') !== 'completed';
}

function cleanup_stale_cli_job_states(string $backup_dir, int $max_age = 86400)
: void {
 cleanup_login_rate_limit_lock_files($backup_dir, $max_age);
 $files = glob($backup_dir . '/.cli_job_*.json') ?: [];
 $now = time();

 $maintenance = read_restore_maintenance($backup_dir);
 if ($maintenance !== [] && empty($maintenance['_invalid'])) {
 $maintenanceJob = (string)($maintenance['job_id'] ?? '');
 $maintenanceJobPath = $maintenanceJob !== ''
 ? $backup_dir . '/.cli_job_' . $maintenanceJob . '.json'
 : '';
 $maintenanceJobState = ($maintenanceJobPath !== '' && is_file($maintenanceJobPath))
 ? json_decode((string)@file_get_contents($maintenanceJobPath), true)
 : null;
 $maintenanceStatus = is_array($maintenanceJobState)
 ? (string)($maintenanceJobState['status'] ?? '')
 : '';
 // Restore durum dosyasını yalnızca işin sonucu güvenilir biçimde
 // yazıldığında temizle. Sadece yaşına bakarak silme; yoksa
 // yazılmışsa temizle. Erken silmek kurtarma bilgisini kaybettirebilir.
 $maintenanceRecovered = is_array($maintenanceJobState) && !empty($maintenanceJobState['recovered']);
 $maintenanceRecoveryRequired = is_array($maintenanceJobState) && !empty($maintenanceJobState['recovery_required']);
 if ($maintenanceJob !== ''
 && ($maintenanceStatus === 'completed' || $maintenanceRecovered)
 && !$maintenanceRecoveryRequired) {
 end_restore_maintenance($backup_dir, $maintenanceJob);
 }
 }

 foreach (glob($backup_dir . '/.vedo_emergency_complete_*.json') ?: [] as $markerPath) {
 if (!is_file($markerPath)) continue;
 $base = basename($markerPath);
 if (!preg_match('/^\.vedo_emergency_complete_([a-f0-9]{32})_([a-f0-9]{32})\.json$/', $base, $m)) continue;
 $parentId = $m[1]; $emergencyId = $m[2];
 $parentState = read_cli_job_state($backup_dir, $parentId);
 if (is_array($parentState)
 && ($parentState['type'] ?? '') === 'restore'
 && !empty($parentState['emergency_backup_completed'])
 && (($parentState['emergency_job_id'] ?? '') === $emergencyId || ($parentState['phase'] ?? '') !== 'emergency_backup')) {
 delete_web_emergency_completion_marker($backup_dir, $parentId, $emergencyId);
 }
 }

 foreach (glob($backup_dir . '/.web_restore_commit_*.json') ?: [] as $markerPath) {
 if (!is_file($markerPath)) continue;
 $base = basename($markerPath);
 if (!preg_match('/^\.web_restore_commit_([a-f0-9]{32})\.json$/', $base, $m)) continue;
 $jobPath = $backup_dir . '/.cli_job_' . $m[1] . '.json';
 if (!is_file($jobPath)) {
 $mtime = (int)@filemtime($markerPath);
 if ($mtime <= 0 || ($now - $mtime) > $max_age) {
 @unlink($markerPath);
 @unlink($markerPath . '.tmp');
 }
 }
 }

 foreach ($files as $path) {
 if (!is_file($path)) continue;

 $raw = @file_get_contents($path);
 $data = is_string($raw) ? json_decode($raw, true) : null;
 if (!is_array($data)) {
 Logger::error('CLI job state JSON bozuk; otomatik silinmeyecek: ' . $path);
 continue;
 }

 $status = (string)($data['status'] ?? '');
 $updatedAt = max(
 0,
 (int)($data['updated_at'] ?? 0),
 (int)@filemtime($path)
 );

 // İş gerçekten bittiyse veya hata ile sonlandıysa durum dosyasını sonsuza kadar tutma.
 // Kısa bir süre daha saklarız ki tarayıcı son sonucu okuyabilsin.
 $terminalStatus = in_array($status, ['completed', 'failed'], true);
 $recoveryRequired = !empty($data['recovery_required']);
 $emergencyJob = !empty($data['is_emergency_backup']);
 if ($terminalStatus
 && !$recoveryRequired
 && !$emergencyJob
 && $updatedAt > 0
 && ($now - $updatedAt) >= VEDO_FINISHED_JOB_STATE_TTL_SECONDS) {
 cleanup_web_restore_stream_cache(is_array($data) ? $data : []);
 $fragmentDir = (string)($data['fragment_dir'] ?? $data['backup_fragment_dir'] ?? '');
 if ($fragmentDir !== '') remove_web_backup_fragment_dir($fragmentDir);

 $finishedJobId = (string)($data['job_id'] ?? '');
 if ($finishedJobId !== '') {
 $finishedMaintenance = read_restore_maintenance($backup_dir);
 if ($finishedMaintenance !== []
 && empty($finishedMaintenance['_invalid'])
 && (string)($finishedMaintenance['job_id'] ?? '') === $finishedJobId
 && empty($finishedMaintenance['recovery_required'])) {
 end_restore_maintenance($backup_dir, $finishedJobId);
 }

 // İş bittiğinde artık ihtiyaç olmayan geçici çalışma dosyalarını kaldır.
 foreach ([
 'backup_tmp_file', 'tmp_file', 'reservation_file', 'backup_reservation_file'
 ] as $artifactKey) {
 $artifact = (string)($data[$artifactKey] ?? '');
 if ($artifact === '') continue;
 $realBackupDir = realpath($backup_dir);
 $realArtifact = realpath($artifact);
 if ($realBackupDir !== false && $realArtifact !== false
 && str_starts_with($realArtifact, $realBackupDir . DIRECTORY_SEPARATOR)
 && (str_ends_with($realArtifact, '.sql.gz.tmp')
 || str_ends_with($realArtifact, '.sql.gz.tmp.reserve'))) {
 @unlink($realArtifact);
 } elseif ($realBackupDir !== false && $realArtifact === false) {
 $candidate = $artifact;
 if (str_starts_with($candidate, $realBackupDir . DIRECTORY_SEPARATOR)
 && (str_ends_with($candidate, '.sql.gz.tmp')
 || str_ends_with($candidate, '.sql.gz.tmp.reserve'))) {
 @unlink($candidate);
 }
 }
 }

 // Restore işleminin son kontrol marker'ı artık bu iş bittikten sonra gerekli değil.
 delete_web_restore_commit_marker($backup_dir, $finishedJobId);

 // Emergency tamamlanma marker'ı varsa parent iş bittiği için artık gerekli değildir.
 foreach (glob($backup_dir . '/.vedo_emergency_complete_' . $finishedJobId . '_*.json*') ?: [] as $markerPath) {
 if (is_file($markerPath)) @unlink($markerPath);
 }

 @unlink($backup_dir . '/.cli_job_' . $finishedJobId . '.json.tmp');
 @unlink($backup_dir . '/.cli_job_' . $finishedJobId . '.state.lock');
 }
 @unlink($path);
 @unlink($path . '.tmp');
 continue;
 }

 // "starting" yalnızca işçi sürecinin ilk HTTP isteği ile gerçek işe geçmesini
 // bekleyen kısa bir geçiş durumudur. İşçi süreç başlayamazsa eski kayıt yeni
 // geri yükleme işlemlerini günlerce kilitlememelidir.
 $recoverableWebRestore = is_recoverable_web_restore_state($data);

 $webPrepareState = ($data['engine'] ?? '') === 'web'
 && ($data['type'] ?? '') === 'restore'
 && ($data['phase'] ?? '') === 'prepare_stream';
 $longRunningWebEmergency = ($data['engine'] ?? '') === 'web'
 && ($data['type'] ?? '') === 'restore'
 && ($data['phase'] ?? '') === 'emergency_backup'
 && !empty($data['emergency_job_id']);

 $protectedRestore = is_nonterminal_restore_state_protected($data);
 $ttl = match ($status) {
 'starting' => 300,
 'waiting' => ($webPrepareState ? VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS : (($recoverableWebRestore || $longRunningWebEmergency || $protectedRestore) ? PHP_INT_MAX : 900)),
 'verifying', 'clearing', 'restoring', 'running' => (($data['type'] ?? '') === 'integrity') ? 86400 : ($webPrepareState ? VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS : (($recoverableWebRestore || $protectedRestore) ? PHP_INT_MAX : 7200)),
 default => min($max_age, 3600)
 };

 // hazırlık işi kendi kaldığı yerden devam penceresine sahiptir. Bu aşamadaki eski bir WEB state,
 // genel geri yükleme koruması tarafından sonsuza kadar korunmamalı; bekleme süresi dolduysa temizlenmelidir.
 $prepareExpired = $webPrepareState
 && $updatedAt > 0
 && ($now - $updatedAt) >= VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS;

 if ($protectedRestore && !$prepareExpired) {
 continue;
 }

 if ($updatedAt > 0 && ($now - $updatedAt) >= $ttl) {
 cleanup_web_restore_stream_cache(is_array($data) ? $data : []);
 $fragmentDir = (string)($data['fragment_dir'] ?? $data['backup_fragment_dir'] ?? '');
 if ($fragmentDir !== '') remove_web_backup_fragment_dir($fragmentDir);
 $staleJobId = (string)($data['job_id'] ?? '');
 if ($webPrepareState
 && $staleJobId !== ''
 && $maintenanceJob === $staleJobId
 && empty($maintenance['recovery_required'])) {
 end_restore_maintenance($backup_dir, $staleJobId);
 }
 @unlink($path);
 @unlink($path . '.tmp');
 }
 }

 // State temizliği tamamlandıktan sonra sahipsiz geçici taraması yapılır; böylece
 // bu çağrıda silinen süresi geçmiş WEB hazırlık kayıtlarının geçici veri akışı dosyası da hemen serbest kalır.
 cleanup_orphan_web_restore_temp_files($backup_dir);

 // Artık karşılık gelen job state'i olmayan eski geçici state dosyalarını da temizle.
 foreach (glob($backup_dir . '/.cli_job_*.json.tmp') ?: [] as $tmpPath) {
 if (!is_file($tmpPath)) continue;
 $base = basename($tmpPath);
 if (!preg_match('/^\.cli_job_([a-f0-9]{32})\.json\.tmp$/', $base, $m)) continue;
 $jobPath = $backup_dir . '/.cli_job_' . $m[1] . '.json';
 if (is_file($jobPath)) continue;
 $mtime = (int)@filemtime($tmpPath);
 if ($mtime > 0 && ($now - $mtime) >= $max_age) @unlink($tmpPath);
 }
 foreach (glob($backup_dir . '/.cli_job_*.state.lock') ?: [] as $lockPath) {
 if (!is_file($lockPath)) continue;
 $base = basename($lockPath);
 if (!preg_match('/^\.cli_job_([a-f0-9]{32})\.state\.lock$/', $base, $m)) continue;
 $jobPath = $backup_dir . '/.cli_job_' . $m[1] . '.json';
 if (is_file($jobPath)) continue;
 $mtime = (int)@filemtime($lockPath);
 if ($mtime > 0 && ($now - $mtime) >= $max_age) @unlink($lockPath);
 }

 // Aktif işlerin kullanmadığı eski geçici
 // dosyaları temizle. Gerçek yedek dosyaları ve onların .sha256/.meta.json
 // dosyaları burada asla silinmez.
 $referencedArtifacts = [];
 foreach (glob($backup_dir . '/.cli_job_*.json') ?: [] as $statePath) {
 if (!is_file($statePath)) continue;
 $data = json_decode((string)@file_get_contents($statePath), true);
 if (!is_array($data)) continue;
 foreach ([
 'backup_tmp_file', 'tmp_file', 'reservation_file', 'backup_reservation_file',
 'backup_target_file', 'target_file', 'fragment_dir', 'backup_fragment_dir',
 'completion_marker', 'restore_stream_path'
 ] as $key) {
 $value = (string)($data[$key] ?? '');
 if ($value !== '') $referencedArtifacts[realpath($value) ?: $value] = true;
 }
 }

 // Tamamlanmış veya yarım kalmış eski geçici gzip dosyaları.
 foreach (glob($backup_dir . '/*.sql.gz.tmp') ?: [] as $tmpGz) {
 if (!is_file($tmpGz)) continue;
 $real = realpath($tmpGz) ?: $tmpGz;
 if (isset($referencedArtifacts[$real])) continue;
 $mtime = (int)@filemtime($tmpGz);
 if ($mtime <= 0 || ($now - $mtime) >= $max_age) {
 @unlink($tmpGz);
 @unlink($tmpGz . '.reserve');
 }
 }

 // Eski WEB yedek parçalarını ve geçici dosyalarını temizle.
 foreach (glob($backup_dir . '/*.sql.gz.tmp.parts') ?: [] as $fragmentDir) {
 if (!is_dir($fragmentDir)) continue;
 $real = realpath($fragmentDir) ?: $fragmentDir;
 if (isset($referencedArtifacts[$real])) continue;
 $mtime = (int)@filemtime($fragmentDir);
 if ($mtime <= 0 || ($now - $mtime) >= $max_age) {
 remove_web_backup_fragment_dir($fragmentDir);
 }
 }

 // Karşılığı kalmayan eski durum dosyalarını temizle.
 foreach (glob($backup_dir . '/.web_restore_commit_*.json*') ?: [] as $markerPath) {
 if (!is_file($markerPath)) continue;
 $mtime = (int)@filemtime($markerPath);
 if ($mtime <= 0 || ($now - $mtime) < $max_age) continue;
 $base = basename($markerPath);
 if (!preg_match('/^\.web_restore_commit_([a-f0-9]{32})\.json(?:\.tmp)?$/', $base, $m)) continue;
 $jobPath = $backup_dir . '/.cli_job_' . $m[1] . '.json';
 if (!is_file($jobPath)) @unlink($markerPath);
 }

 foreach (glob($backup_dir . '/.vedo_emergency_complete_*.json*') ?: [] as $markerPath) {
 if (!is_file($markerPath)) continue;
 $mtime = (int)@filemtime($markerPath);
 if ($mtime <= 0 || ($now - $mtime) < $max_age) continue;
 $base = basename($markerPath);
 if (!preg_match('/^\.vedo_emergency_complete_([a-f0-9]{32})_([a-f0-9]{32})\.json(?:\.tmp)?$/', $base, $m)) continue;
 $parentJobPath = $backup_dir . '/.cli_job_' . $m[1] . '.json';
 $emergencyJobPath = $backup_dir . '/.cli_job_' . $m[2] . '.json';
 if (!is_file($parentJobPath) && !is_file($emergencyJobPath)) @unlink($markerPath);
 }

 // Tek başına kalmış reservation ve giriş durumu geçici dosyalarını da temizle.
 foreach (glob($backup_dir . '/*.sql.gz.tmp.reserve') ?: [] as $reservePath) {
 if (!is_file($reservePath)) continue;
 $real = realpath($reservePath) ?: $reservePath;
 if (isset($referencedArtifacts[$real])) continue;
 $mtime = (int)@filemtime($reservePath);
 if ($mtime <= 0 || ($now - $mtime) >= $max_age) @unlink($reservePath);
 }
 foreach (glob($backup_dir . '/.login_rate_*.json.tmp') ?: [] as $rateTmp) {
 if (!is_file($rateTmp)) continue;
 $base = basename($rateTmp);
 if (!preg_match('/^\.login_rate_[a-f0-9]{64}\.json\.tmp$/', $base)) continue;
 $mtime = (int)@filemtime($rateTmp);
 if ($mtime <= 0 || ($now - $mtime) >= $max_age) @unlink($rateTmp);
 }

 // Giriş deneme durumları da süresiz birikmesin. Aktif kilit yoksa ve son kayıt
 // yeterince eskiyse dosyayı kaldır.
 foreach (glob($backup_dir . '/.login_rate_*.json') ?: [] as $ratePath) {
 if (!is_file($ratePath)) continue;
 $raw = @file_get_contents($ratePath);
 $data = is_string($raw) ? json_decode($raw, true) : null;
 $updatedAt = is_array($data) ? (int)($data['updated_at'] ?? 0) : 0;
 $lockedUntil = is_array($data) ? (int)($data['locked_until'] ?? 0) : 0;
 $mtime = (int)@filemtime($ratePath);
 $lastTouch = max(0, $updatedAt, $mtime);
 if ($lockedUntil > $now) continue;
 if ($lastTouch > 0 && ($now - $lastTouch) >= $max_age) {
 $base = basename($ratePath);
 if (preg_match('/^\.login_rate_[a-f0-9]{64}\.json$/', $base)) @unlink($ratePath);
 }
 }
}


function find_active_cli_job_states(string $backup_dir)
: array {
 $active = [];
 $files = glob($backup_dir . '/.cli_job_*.json') ?: [];

 foreach ($files as $path) {
 if (!is_file($path)) continue;
 $data = json_decode((string)@file_get_contents($path), true);
 if (!is_array($data)) continue;
 if (!empty($data['is_emergency_backup'])) continue;
 if (!in_array((string)($data['type'] ?? ''), ['backup', 'restore'], true)) continue;

 $status = (string)($data['status'] ?? '');
 if (!in_array($status, ['starting', 'verifying', 'waiting', 'running', 'clearing', 'restoring'], true)) {
 continue;
 }

 $updatedAt = max(
 0,
 (int)($data['updated_at'] ?? 0),
 (int)@filemtime($path)
 );
 $age = $updatedAt > 0 ? max(0, time() - $updatedAt) : PHP_INT_MAX;
 $webPrepareState = ($data['engine'] ?? '') === 'web'
 && ($data['type'] ?? '') === 'restore'
 && ($data['phase'] ?? '') === 'prepare_stream';
 $recoverableWebRestore = is_recoverable_web_restore_state($data);
 $ttl = match ($status) {
 'starting' => 300,
 'waiting' => $webPrepareState ? VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS : ($recoverableWebRestore ? PHP_INT_MAX : 900),
 'verifying', 'clearing', 'restoring', 'running' => $webPrepareState ? VEDO_WEB_RESTORE_PREP_STALE_TTL_SECONDS : ($recoverableWebRestore ? PHP_INT_MAX : 7200),
 default => 3600
 };
 if ($age > $ttl) {
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
function acquire_job_admission_lock(string $backup_dir)
: mixed {
 return acquire_system_lock($backup_dir, 'job_admission', 30);
}

function release_job_admission_lock(mixed $lock_handle)
: void {
 release_system_lock($lock_handle);
}

function assert_no_active_database_job(string $backup_dir, string $ignore_job_id = '')
: void {
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
// PAYLAŞIMLI HOST: CLI/exec/proc_open kullanılamıyorsa Web işçi süreci yedeği kullanılabilir.
function detect_cli_worker_capability()
: array {
 $result = [
 'available' => false,
 'reason' => '',
 'php_binary' => '',
 'missing_extensions' => []
 ];

 if (!function_exists('exec') && !function_exists('proc_open')) {
 $result['reason'] = 'exec() ve proc_open() kullanılabilir değil.';
 return $result;
 }

 // Panel tarafından başlatılan normal CLI işler için veri tabanı erişimi gerekir.
 // WEB geri yükleme hiçbir noktada bu capability kontrolüne ihtiyaç duymaz.
 $requiredExtensions = ['pdo', 'pdo_mysql', 'json', 'zlib', 'hash'];

 try {
 $php = resolve_cli_php_binary();
 $result['php_binary'] = $php;
 $probeCode = 'echo PHP_SAPI, "\\n"; foreach (' . var_export($requiredExtensions, true) . ' as $ext) { if (!extension_loaded($ext)) echo "MISSING:" . $ext . "\\n"; }';
 $command = escapeshellarg($php) . ' -r ' . escapeshellarg($probeCode);

 $output = [];
 $stderr = '';
 $exitCode = 1;

 if (function_exists('exec')) {
 @exec($command, $output, $exitCode);
 $stdout = implode("\n", array_map('strval', $output));
 if ($exitCode === 0) {
 $lines = preg_split('/\R/', trim($stdout)) ?: [];
 $sapi = trim((string)array_shift($lines));
 $missing = [];
 foreach ($lines as $line) {
 if (str_starts_with($line, 'MISSING:')) {
 $ext = trim(substr($line, 8));
 if ($ext !== '') $missing[] = $ext;
 }
 }
 if ($sapi === 'cli' && $missing === []) {
 $result['available'] = true;
 return $result;
 }
 $result['missing_extensions'] = array_values(array_unique($missing));
 if ($sapi !== 'cli') {
 $result['reason'] = 'Bulunan PHP binary CLI SAPI ile çalışmıyor.';
 } elseif ($missing !== []) {
 $result['reason'] = 'CLI PHP gerekli uzantılara sahip değil: ' . implode(', ', $missing);
 } else {
 $result['reason'] = 'CLI PHP doğrulaması başarısız.';
 }
 }
 }

 if (function_exists('proc_open')) {
 $descriptor = [
 0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'],
 1 => ['pipe', 'w'],
 2 => ['pipe', 'w']
 ];
 $proc = @proc_open($command, $descriptor, $pipes);
 if (is_resource($proc)) {
 $stdout = trim((string)stream_get_contents($pipes[1]));
 $stderr = trim((string)stream_get_contents($pipes[2]));
 foreach ($pipes as $pipe) {
 if (is_resource($pipe)) @fclose($pipe);
 }
 $exitCode = @proc_close($proc);
 if ($exitCode === 0) {
 $lines = preg_split('/\R/', $stdout) ?: [];
 $sapi = trim((string)array_shift($lines));
 $missing = [];
 foreach ($lines as $line) {
 if (str_starts_with($line, 'MISSING:')) {
 $ext = trim(substr($line, 8));
 if ($ext !== '') $missing[] = $ext;
 }
 }
 $result['missing_extensions'] = array_values(array_unique($missing));
 if ($sapi === 'cli' && $result['missing_extensions'] === []) {
 $result['available'] = true;
 return $result;
 }
 if ($sapi !== 'cli') {
 $result['reason'] = 'Bulunan PHP binary CLI SAPI ile çalışmıyor.';
 } elseif ($result['missing_extensions'] !== []) {
 $result['reason'] = 'CLI PHP gerekli uzantılara sahip değil: ' . implode(', ', $result['missing_extensions']);
 }
 } elseif ($stderr !== '') {
 $result['reason'] = $stderr;
 }
 }
 }
 } catch (Throwable $e) {
 $result['reason'] = $e->getMessage();
 }

 if ($result['reason'] === '') {
 $result['reason'] = 'PHP CLI worker gerekli uzantılarla doğrulanamadı.';
 }
 return $result;
}

function build_web_backup_paths(string $backup_dir, string $db_name, string $job_id = '')
: array {
 if ($job_id !== '' && !preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 throw new Exception('Geçersiz Web Worker job ID.');
 }

 $suffix = $job_id !== '' ? '_' . $job_id : '';
 $base = $backup_dir . '/' . $db_name . '_' . gmdate('Y-m-d_H-i') . 'UTC_web' . $suffix;

 $target = $base . '.sql.gz';
 $tmp = $target . '.tmp';

 // İş kimliği tabanlı isimler çakışmayı pratikte ortadan kaldırır.
 // Ek olarak O_EXCL ile boş bir rezervasyon dosyası atomik oluşturulur.
 // Böylece iki aynı iş kimliği isteği bile aynı işi ikinci kez başlatamaz.
 $reservation = $tmp . '.reserve';

 $fp = @fopen($reservation, 'x');
 if ($fp === false) {
 throw new Exception('Bu Web Worker backup işi için dosya rezervasyonu zaten mevcut.');
 }
 fclose($fp);

 return [
 'target' => $target,
 'tmp' => $tmp,
 'reservation' => $reservation
 ];
}

function get_web_worker_tables(PDO $pdo, string $db_name)
: array {
 $stmt = $pdo->prepare("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' AND UPPER(COALESCE(ENGINE, '')) <> 'SEQUENCE' ORDER BY TABLE_NAME");
 $stmt->execute([$db_name]);
 $tables = array_values(array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN)));
 $stmt->closeCursor();
 return $tables;
}

function ensure_web_backup_fragment_dir(string $fragmentDir)
: void {
 if ($fragmentDir === '') throw new Exception('Web backup fragment dizini eksik.');
 if (!is_dir($fragmentDir) && !@mkdir($fragmentDir, 0700, true) && !is_dir($fragmentDir)) {
 throw new Exception('Web backup fragment dizini oluşturulamadı.');
 }
}
function web_backup_fragment_path(string $fragmentDir, int $tableIndex, string $kind, int $chunkIndex = 0)
: string {
 ensure_web_backup_fragment_dir($fragmentDir);
 $kind = preg_replace('/[^A-Za-z0-9_-]/', '_', $kind) ?: 'part';
 return rtrim($fragmentDir, '/\\') . '/' . sprintf('%06d', $tableIndex) . '_' . $kind . '_' . sprintf('%06d', $chunkIndex) . '.sql.gz';
}
function web_backup_static_fragment_path(string $fragmentDir, string $name)
: string {
 ensure_web_backup_fragment_dir($fragmentDir);
 if (!preg_match('/^[A-Za-z0-9_.-]+$/', $name)) throw new Exception('Geçersiz Web backup fragment adı.');
 return rtrim($fragmentDir, '/\\') . '/' . $name . '.sql.gz';
}
function web_backup_fragment_meta_path(string $fragmentPath)
: string { return $fragmentPath . '.meta.json'; }
function encode_web_cursor_values(array $values)
: array {
 $result = [];
 foreach ($values as $value) {
 if ($value === null) $result[] = ['t' => 'n', 'v' => null];
 elseif (is_int($value)) $result[] = ['t' => 'i', 'v' => $value];
 elseif (is_float($value)) $result[] = ['t' => 'f', 'v' => (string)$value];
 elseif (is_bool($value)) $result[] = ['t' => 'b', 'v' => $value ? 1 : 0];
 else $result[] = ['t' => 's', 'v' => base64_encode((string)$value)];
 }
 return $result;
}
function decode_web_cursor_values(array $encoded)
: array {
 $result = [];
 foreach ($encoded as $item) {
 if (!is_array($item)) { $result[] = null; continue; }
 $type = (string)($item['t'] ?? 'n'); $value = $item['v'] ?? null;
 $result[] = match ($type) {
 'i' => (int)$value,
 'f' => (float)$value,
 'b' => (bool)$value,
 's' => (($decoded = base64_decode((string)$value, true)) !== false ? $decoded : ''),
 default => null,
 };
 }
 return $result;
}
function write_web_backup_gzip_fragment(string $fragmentPath, callable $writer)
: void {
 $tmp = $fragmentPath . '.tmp'; @unlink($tmp);
 $gz = @gzopen($tmp, 'wb3');
 if ($gz === false) throw new Exception('Web backup fragment gzip dosyası oluşturulamadı.');
 try { $writer($gz); } catch (Throwable $e) { @gzclose($gz); @unlink($tmp); throw $e; }
 if (@gzclose($gz) === false) { @unlink($tmp); throw new Exception('Web backup fragment gzip dosyası kapatılırken hata oluştu.'); }
 if (!is_file($tmp) || (int)@filesize($tmp) <= 0) { @unlink($tmp); throw new Exception('Web backup fragment boş oluşturuldu.'); }
 if (!@rename($tmp, $fragmentPath)) { @unlink($tmp); throw new Exception('Web backup fragment finalize edilemedi.'); }
}
function append_web_backup_fragment_idempotent(string $fragmentPath, string $targetPath)
: void {
 if (!is_file($fragmentPath)) throw new Exception('Web backup fragment bulunamadı: ' . basename($fragmentPath));
 $fragmentSize = (int)@filesize($fragmentPath);
 if ($fragmentSize <= 0) throw new Exception('Web backup fragment boş: ' . basename($fragmentPath));

 $fragmentHash = @hash_file('sha256', $fragmentPath);
 if (!is_string($fragmentHash) || !preg_match('/^[a-f0-9]{64}$/i', $fragmentHash)) {
 throw new Exception('Web backup fragment checksum hesaplanamadı: ' . basename($fragmentPath));
 }
 $journalPath = $fragmentPath . '.append.json';

 $fp = @fopen($targetPath, 'c+b');
 if ($fp === false) throw new Exception('Web backup ana geçici dosyası açılamadı.');
 $locked = false;
 try {
 if (!@flock($fp, LOCK_EX)) throw new Exception('Web backup ana geçici dosya kilidi alınamadı.');
 $locked = true;
 $targetSize = (int)(@fstat($fp)['size'] ?? 0);

 // Parça zaten ana geçici dosyanın tam sonuysa daha önce yazılmıştır; yalnızca durum
 // kaydı sonradan başarısız olmuş olabilir. Bu parçayı ikinci kez ekleme.
 if (!is_file($journalPath) && $targetSize >= $fragmentSize && @fseek($fp, $targetSize - $fragmentSize, SEEK_SET) === 0) {
 $fragmentFp = @fopen($fragmentPath, 'rb');
 if ($fragmentFp !== false) {
 $matchesTail = true;
 try {
 $remaining = $fragmentSize;
 while ($remaining > 0) {
 $fragmentChunk = fread($fragmentFp, min(1048576, $remaining));
 $targetChunk = fread($fp, min(1048576, $remaining));
 if ($fragmentChunk === false || $targetChunk === false || $fragmentChunk === '' || $targetChunk === '' || !hash_equals($fragmentChunk, $targetChunk)) {
 $matchesTail = false;
 break;
 }
 $remaining -= strlen($fragmentChunk);
 }
 } finally { @fclose($fragmentFp); }
 if ($matchesTail) {
 @fseek($fp, 0, SEEK_END);
 return;
 }
 }
 }

 $journal = null;
 if (is_file($journalPath)) {
 $rawJournal = @file_get_contents($journalPath);
 $journal = is_string($rawJournal) ? json_decode($rawJournal, true) : null;
 if (!is_array($journal)
 || strtolower((string)($journal['fragment_sha256'] ?? '')) !== strtolower($fragmentHash)
 || (int)($journal['fragment_size'] ?? -1) !== $fragmentSize
 ) {
 throw new Exception('Web backup fragment append journal geçersiz veya fragment değişmiş.');
 }
 } else {
 $journal = [
 'fragment_sha256' => strtolower($fragmentHash),
 'fragment_size' => $fragmentSize,
 'original_end' => $targetSize,
 'created_at' => time(),
 ];
 $journalJson = json_encode($journal, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
 if (!safe_file_put_contents($journalPath . '.tmp', $journalJson, LOCK_EX) || !@rename($journalPath . '.tmp', $journalPath)) {
 @unlink($journalPath . '.tmp');
 throw new Exception('Web backup fragment append journal yazılamadı.');
 }
 }

 $originalEnd = (int)($journal['original_end'] ?? -1);
 if ($originalEnd < 0 || $originalEnd > $targetSize) {
 throw new Exception('Web backup fragment append başlangıç konumu geçersiz.');
 }

 // Crash sırasında hedef dosyası parça'in yalnızca bir kısmını almışsa,
 // journal sayesinde o kısmi ek güvenle geri alınır ve parça baştan eklenir.
 if ($targetSize > $originalEnd) {
 $extra = $targetSize - $originalEnd;
 if ($extra >= $fragmentSize) {
 if ($extra > $fragmentSize) {
 throw new Exception('Web backup ana dosyasında beklenmeyen fazla veri tespit edildi.');
 }

 $fragmentFp = @fopen($fragmentPath, 'rb');
 if ($fragmentFp === false) throw new Exception('Web backup fragment doğrulama için açılamadı.');
 $matchesFull = true;
 try {
 if (@fseek($fp, $originalEnd, SEEK_SET) !== 0) $matchesFull = false;
 $remaining = $fragmentSize;
 while ($matchesFull && $remaining > 0) {
 $fragmentChunk = fread($fragmentFp, min(1048576, $remaining));
 $targetChunk = fread($fp, min(1048576, $remaining));
 if ($fragmentChunk === false || $targetChunk === false || $fragmentChunk === '' || $targetChunk === '' || !hash_equals($fragmentChunk, $targetChunk)) {
 $matchesFull = false;
 break;
 }
 $remaining -= strlen($fragmentChunk);
 }
 } finally { @fclose($fragmentFp); }

 if ($matchesFull) {
 @unlink($journalPath);
 @fseek($fp, 0, SEEK_END);
 return;
 }
 throw new Exception('Web backup ana dosyasının son fragment içeriği beklenenden farklı.');
 }

 $fragmentFp = @fopen($fragmentPath, 'rb');
 if ($fragmentFp === false) throw new Exception('Web backup fragment doğrulama için açılamadı.');
 $matchesPrefix = true;
 try {
 if (@fseek($fragmentFp, 0, SEEK_SET) !== 0 || @fseek($fp, $originalEnd, SEEK_SET) !== 0) {
 $matchesPrefix = false;
 }
 $remaining = $extra;
 while ($matchesPrefix && $remaining > 0) {
 $fragmentChunk = fread($fragmentFp, min(1048576, $remaining));
 $targetChunk = fread($fp, min(1048576, $remaining));
 if ($fragmentChunk === false || $targetChunk === false || $fragmentChunk === '' || $targetChunk === '' || !hash_equals($fragmentChunk, $targetChunk)) {
 $matchesPrefix = false;
 break;
 }
 $remaining -= strlen($fragmentChunk);
 }
 } finally { @fclose($fragmentFp); }
 if (!$matchesPrefix) {
 throw new Exception('Web backup ana dosyasındaki yarım fragment beklenen prefix ile eşleşmiyor.');
 }
 if (!@ftruncate($fp, $originalEnd) || !@fflush($fp)) {
 throw new Exception('Web backup ana dosyasındaki yarım fragment geri alınamadı.');
 }
 $targetSize = $originalEnd;
 }

 // Günlük dosyası yeniden oluşturulmuş olsa bile önceden kaydedilmiş tam son parça kabul edilir.
 if ($targetSize === $originalEnd) {
 if (@fseek($fp, $originalEnd, SEEK_SET) !== 0) throw new Exception('Web backup ana dosyasına append konumu ayarlanamadı.');
 $src = @fopen($fragmentPath, 'rb');
 if ($src === false) throw new Exception('Web backup fragment okunamadı.');
 try {
 $written = 0;
 while (!feof($src)) {
 $chunk = fread($src, 1048576);
 if ($chunk === false) throw new Exception('Web backup fragment okunurken hata oluştu.');
 if ($chunk === '') continue;
 $off = 0; $len = strlen($chunk);
 while ($off < $len) {
 $n = fwrite($fp, substr($chunk, $off));
 if ($n === false || $n === 0) throw new Exception('Web backup fragment ana dosyaya eklenemedi.');
 $off += $n; $written += $n;
 }
 }
 if ($written !== $fragmentSize || !@fflush($fp)) throw new Exception('Web backup fragment ana dosyaya tam yazılamadı.');
 } finally { @fclose($src); }
 }

 if ((int)(@fstat($fp)['size'] ?? 0) !== $originalEnd + $fragmentSize) {
 throw new Exception('Web backup fragment append sonucu beklenen boyuta ulaşmadı.');
 }
 @unlink($journalPath);
 } finally { if ($locked) @flock($fp, LOCK_UN); @fclose($fp); }
}
function remove_web_backup_fragment_dir(string $fragmentDir)
: void {
 if ($fragmentDir === '' || !is_dir($fragmentDir)) return;
 $items = @scandir($fragmentDir);
 if (!is_array($items)) return;
 foreach ($items as $item) {
 if ($item === '.' || $item === '..') continue;
 $full = $fragmentDir . DIRECTORY_SEPARATOR . $item;
 if (is_dir($full) && !is_link($full)) remove_web_backup_fragment_dir($full); else @unlink($full);
 }
 @rmdir($fragmentDir);
}
function web_backup_table_definition(PDO $pdo, string $db_name, string $table)
: array {
 if (!is_db_identifier_safe($table)) throw new Exception('Geçersiz tablo tanımı tespit edildi.');
 $stmt = $pdo->prepare("SHOW CREATE TABLE `{$table}`"); $stmt->execute();
 $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: []; $stmt->closeCursor();
 $create = (string)($row['Create Table'] ?? '');
 if ($create === '') throw new Exception('Tablo şeması okunamadı: ' . $table);
 return [
 'sql' => "\nDROP TABLE IF EXISTS `{$table}`;\n{$create};\n\n",
 'columns' => get_table_columns($pdo, $db_name, $table),
 'cursor_keys' => get_table_cursor_keys($pdo, $db_name, $table)
 ];
}
// WEB restore tabloları tek tek işler. CLI restore farklı bir çalışma biçimi kullanır.
// Bunun nedeni shared hosting HTTP istekleri arasında aynı PDO transactionının güvenilir biçimde korunamamasıdır.
/**
 * WEB çalışanı bir seferde küçük bir yedek parçası işler. İş durumunu kaydeder ve sonraki istekte kaldığı yerden devam eder.
 */

// =============================================================================
// PHP - WEB TABANLI YEDEKLEME İŞÇİSİ

/*
WEB işçi süreç NEDİR?
Her sunucu PHP CLI süreci başlatmaya izin vermeyebilir.
Özellikle bazı paylaşımlı hosting ortamlarında exec/proc_open
gibi imkanlar kapalı olabilir.

Bu durumda WEB işçi süreç yedekleme işini küçük HTTP adımlarına böler.

Akış:
Tarayıcı → PHP adımı → durum dosyası → tarayıcı tekrar sorar
 → PHP sonraki adımı çalıştırır → ...

Avantajı:
CLI kapalı olsa bile uzun işlem için bir alternatif sunar.

Dezavantajı:
Tarayıcının ilerleme sorguları bu modelde işin sonraki adımlarını
tetikleyebilir. Tarayıcı tamamen durursa WEB işçi süreç'ın ilerlemesi
de durabilir. Ayrıca WEB yedekleme modeli, ayrı HTTP istekleri
nedeniyle CLI kadar tek parça bir çalışma ortamı değildir.

Bu nedenle programda CLI mümkünse tavsiye edilir; WEB işçi süreç
uyumluluk/yedek çalışma yöntemidir.
*/

// Uzun süren yedeklemeyi tek HTTP isteğinde bitirmek yerine küçük adımlara böler.
// Tarayıcı ilerleme durumunu sordukça bir sonraki adım çalıştırılır.
// =============================================================================

function web_backup_step(
 PDO $pdo,
 string $job_id,
 string $backup_dir,
 array $config,
 string $state_prefix = 'backup',
 ?array $state_override = null
)
: array {
 $state = $state_override ?? read_cli_job_state($backup_dir, $job_id);
 if (!$state) throw new Exception('Web Worker durum dosyası bulunamadı.');
 if ((int)($state['web_backup_protocol'] ?? 0) !== 2) throw new Exception('Eski Web backup iş formatı desteklenmiyor; yeni backup işi başlatılmalıdır.');

 $tables = array_values(array_map('strval', $state[$state_prefix . '_tables'] ?? $state['tables'] ?? []));
 $indexKey = $state_prefix . '_table_index';
 $rowsKey = $state_prefix . '_processed_rows';
 $tmpKey = $state_prefix . '_tmp_file';
 $targetKey = $state_prefix . '_target_file';
 $tmpFile = (string)($state[$tmpKey] ?? ''); $targetFile = (string)($state[$targetKey] ?? '');
 $fragmentDir = (string)($state[$state_prefix . '_fragment_dir'] ?? $state['fragment_dir'] ?? ($tmpFile . '.parts'));
 if ($tmpFile === '' || $targetFile === '') throw new Exception('Web Worker backup dosya yolları eksik.');
 ensure_web_backup_fragment_dir($fragmentDir);

 $index = (int)($state[$indexKey] ?? 0); $processedRows = (int)($state[$rowsKey] ?? 0);
 $stepStarted = microtime(true); $webBudget = get_dynamic_web_step_budget($backup_dir); $maxStepSeconds = (float)$webBudget['max_step_seconds']; $maxChunks = (int)$webBudget['max_chunks'];

 if (empty($state['header_committed'])) {
 $fragment = web_backup_static_fragment_path($fragmentDir, '000000_header');
 if (!is_file($fragment)) {
 write_web_backup_gzip_fragment($fragment, static function ($gz) use ($state): void {
 safe_gzwrite($gz,
 "-- VEDO MYSQL BACKUP [WEB WORKER]\n" .
 "-- DB: {$state['db_name']}\n" .
 "-- TIME: " . date('Y-m-d H:i:s') . "\n" .
 "-- FORMAT: CONCATENATED GZIP MEMBERS\n" .
 "-- CONSISTENCY: PER-TABLE READ LOCK (NO GLOBAL SNAPSHOT ACROSS HTTP REQUESTS)\n" .
 "SET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\n\n"
 );
 });
 }
 append_web_backup_fragment_idempotent($fragment, $tmpFile);
 $state['header_committed'] = true; write_cli_job_state($backup_dir, $job_id, $state); @unlink($fragment);
 }

 if (empty($state['sequences_exported'])) {
 $fragment = web_backup_static_fragment_path($fragmentDir, '000001_sequences');
 if (!is_file($fragment)) {
 write_web_backup_gzip_fragment($fragment, static function ($gz) use ($pdo, $state): void {
 $count = export_database_sequences_to_stream($pdo, $state['db_name'], $gz);
 safe_gzwrite($gz, "-- SEQUENCES EXPORTED BEFORE TABLES: {$count}\n\n");
 });
 }
 append_web_backup_fragment_idempotent($fragment, $tmpFile);
 $state['sequences_exported'] = true; write_cli_job_state($backup_dir, $job_id, $state); @unlink($fragment);
 }

 while ($index < count($tables) && $maxChunks > 0 && (microtime(true) - $stepStarted) < $maxStepSeconds) {
 if (($state['web_table_state']['table_index'] ?? -1) !== $index) {
 $state['web_table_state'] = [
 'table_index' => $index, 'table_name' => (string)($tables[$index] ?? ''),
 'table_started_at' => microtime(true), 'estimated_rows' => 0,
 'initialized' => false, 'schema_done' => false,
 'chunk_index' => 1, 'offset' => 0, 'last_values' => [], 'rows_for_table' => 0,
 'done' => false
 ];
 write_cli_job_state($backup_dir, $job_id, $state);
 }
 $tableState = is_array($state['web_table_state'] ?? null) ? $state['web_table_state'] : [];
 $table = $tables[$index];

 // WEB çalışanının hangi tabloda olduğunu her adımın başında durum kaydına yaz.
 // Arayüz bu alanı doğrudan "AKTİF TABLO" kutusunda gösterir. Önceki sürümde
 // tablo adı yalnızca yerel değişkende kalıyor, bu yüzden arayüz '-' gösteriyordu.
 $state['current_table'] = $table;
 $state['current_table_index'] = $index + 1; // Kullanıcıya 1 tabanlı sıra göster.
 $state['total_tables'] = count($tables);
 if (($tableState['table_name'] ?? '') !== $table) {
 $tableState['table_name'] = $table;
 $tableState['table_started_at'] = microtime(true);
 $tableState['estimated_rows'] = 0;
 $tableState['rows_for_table'] = 0;
 $state['web_table_state'] = $tableState;
 } elseif (empty($tableState['table_started_at'])) {
 $tableState['table_started_at'] = microtime(true);
 $state['web_table_state'] = $tableState;
 }
 write_cli_job_state($backup_dir, $job_id, $state);

 if (!$tableState['initialized']) {
 $quoted = '`' . str_replace('`', '``', $table) . '`'; $locked = false;
 try {
 $pdo->exec("LOCK TABLES {$quoted} READ");
 $locked = true;
 $definition = web_backup_table_definition($pdo, $state['db_name'], $table);
 $rowEstimateStmt = $pdo->prepare("SELECT COALESCE(TABLE_ROWS, 0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?");
 $rowEstimateStmt->execute([$state['db_name'], $table]);
 $tableState['estimated_rows'] = max(0, (int)($rowEstimateStmt->fetchColumn() ?? 0));
 $rowEstimateStmt->closeCursor();
 }
 finally { if ($locked) { try { $pdo->exec('UNLOCK TABLES'); } catch (Throwable $e) { Logger::warning('Web backup schema READ LOCK bırakılamadı [' . $table . ']: ' . $e->getMessage()); } } }
 $tableState['initialized'] = true;
 $tableState['columns_select'] = $definition['columns'];
 $tableState['cursor_keys'] = $definition['cursor_keys'];
 $tableState['use_keyset'] = !empty($definition['cursor_keys']);
 $tableState['generated_only'] = ($definition['columns'] === '');

 // PRIMARY/UNIQUE keyset imleci bulunmayan normal tablolar için daha önce
 // işi tamamen durduran bir güvenlik kontrolü vardı. Bu, joomla_fields_values
 // gibi geçerli tabloları WEB çalışanından haksız yere çıkarıyordu.
 // Şimdi deterministik ORDER BY + OFFSET yedek yol kullanıyoruz. yedek yol sırası
 // durum kaydına bir kez yazılıyor. Sonraki web isteklerinde tablo yapısı tekrar okunmuyor.
 if (!$tableState['use_keyset'] && !$tableState['generated_only']) {
 $fallbackOrder = get_table_fallback_order_by($pdo, $state['db_name'], $table);
 if ($fallbackOrder === '') {
 throw new Exception('WEB backup için güvenli fallback sırası üretilemedi: ' . $table . '.');
 }
 $tableState['pagination_mode'] = 'ordered_offset_fallback';
 $tableState['fallback_order_by'] = $fallbackOrder;
 Logger::warning('WEB backup keyset olmayan tablo için ORDER BY + OFFSET fallback kullanıyor | table=' . $table);
 } else {
 $tableState['pagination_mode'] = $tableState['generated_only'] ? 'generated_only' : 'keyset';
 $tableState['fallback_order_by'] = '';
 }
 $schemaFragment = web_backup_fragment_path($fragmentDir, $index, 'schema', 0);
 if (!is_file($schemaFragment)) write_web_backup_gzip_fragment($schemaFragment, static function ($gz) use ($definition): void { safe_gzwrite($gz, $definition['sql']); });
 append_web_backup_fragment_idempotent($schemaFragment, $tmpFile);
 $tableState['schema_done'] = true; $state['web_table_state'] = $tableState; write_cli_job_state($backup_dir, $job_id, $state); @unlink($schemaFragment);
 }

 $chunkIndex = (int)($tableState['chunk_index'] ?? 1);
 $fragmentPath = web_backup_fragment_path($fragmentDir, $index, 'data', $chunkIndex);
 $metaPath = web_backup_fragment_meta_path($fragmentPath);

 if (is_file($fragmentPath) || is_file($metaPath)) {
 if (!is_file($fragmentPath) || !is_file($metaPath)) { @unlink($fragmentPath); @unlink($metaPath); }
 else {
 $raw = @file_get_contents($metaPath); $meta = is_string($raw) ? json_decode($raw, true) : null;
 if (!is_array($meta)) { @unlink($fragmentPath); @unlink($metaPath); continue; }
 append_web_backup_fragment_idempotent($fragmentPath, $tmpFile);
 $metaRows = (int)($meta['rows'] ?? 0);
 $metaNextChunk = (int)($meta['next_chunk_index'] ?? ($chunkIndex + 1));
 $currentCheckpointChunk = (int)($tableState['chunk_index'] ?? $chunkIndex);

 // Parça ana yedeğe eklenmiş olabilir ve durum kaydı da
 // daha önce yazılmış olabilir. Bu durumda fragmenti tekrar eklemek gerekmez
 // (append yardımcı bunu engeller) ve satır sayaçlarını ikinci kez artırmak da
 // kesinlikle yapılmamalıdır.
 if ($currentCheckpointChunk < $metaNextChunk) {
 $processedRows += $metaRows;
 $tableState['rows_for_table'] = (int)($tableState['rows_for_table'] ?? 0) + $metaRows;
 } elseif ($currentCheckpointChunk > $metaNextChunk) {
 throw new Exception('Web backup fragment checkpoint sırası bozulmuş: state ileride, fragment geride.');
 }

 $tableState['chunk_index'] = $metaNextChunk;
 $tableState['offset'] = (int)($meta['next_offset'] ?? ($tableState['offset'] ?? 0));
 $tableState['last_values'] = $meta['next_last_values'] ?? ($tableState['last_values'] ?? []);
 $tableState['done'] = !empty($meta['done']);
 $state['web_table_state'] = $tableState;
 $state[$rowsKey] = $processedRows;
 write_cli_job_state($backup_dir, $job_id, $state);
 // Durum kaydı kalıcılaştıktan sonra parçayı kaldır. Böylece çökme sonrası tekrar
 // çalıştırma aynı parçayı ikinci kez eklemez.
 @unlink($fragmentPath);
 @unlink($metaPath);
 if ($tableState['done']) {
 $index++;
 $state[$indexKey] = $index;
 $state['current_table_index'] = min($index + 1, count($tables));
 $state['current_table'] = $index < count($tables) ? (string)$tables[$index] : 'Tamamlandı';
 $state['web_table_state'] = [];
 write_cli_job_state($backup_dir, $job_id, $state);
 }
 $maxChunks--; continue;
 }
 }

 $quotedTable = '`' . str_replace('`', '``', $table) . '`'; $locked = false; $rowsExported = 0; $nextOffset = (int)($tableState['offset'] ?? 0); $nextLast = $tableState['last_values'] ?? []; $done = false;
 try {
 $pdo->exec("LOCK TABLES {$quotedTable} READ"); $locked = true;
 if (!empty($tableState['generated_only'])) {
 if (!isset($tableState['generated_total_rows'])) {
 $st = $pdo->query("SELECT COUNT(*) FROM {$quotedTable}");
 $tableState['generated_total_rows'] = $st ? (int)$st->fetchColumn() : 0;
 if ($st) $st->closeCursor();
 $tableState['estimated_rows'] = (int)$tableState['generated_total_rows'];
 }
 $remaining = max(0, (int)$tableState['generated_total_rows'] - $nextOffset);
 if ($remaining === 0) { $done = true; }
 else {
 $rowsExported = min(250, $remaining);
 write_web_backup_gzip_fragment($fragmentPath, static function ($gz) use ($table, $rowsExported): void {
 safe_gzwrite($gz, "INSERT INTO `{$table}` () VALUES\n" . implode(",\n", array_fill(0, $rowsExported, '()')) . ";\n");
 });
 $nextOffset += $rowsExported; $done = ($nextOffset >= (int)$tableState['generated_total_rows']);
 }
 } else {
 $columns = (string)$tableState['columns_select']; $keys = array_values(array_map('strval', $tableState['cursor_keys'] ?? [])); $useKeyset = !empty($keys); $chunkSize = min(500, max(100, calculate_adaptive_chunk_size($pdo, $state['db_name'], $table))); $stmt = null; $lastRaw = decode_web_cursor_values(is_array($tableState['last_values'] ?? null) ? $tableState['last_values'] : []);
 if ($useKeyset) {
 $quotedKeys = array_map(static fn($k) => '`' . str_replace('`', '``', $k) . '`', $keys); $order = implode(', ', $quotedKeys);
 if ($lastRaw === []) $stmt = $pdo->prepare("SELECT {$columns} FROM {$quotedTable} ORDER BY {$order} LIMIT :limit");
 elseif (count($keys) === 1) { $stmt = $pdo->prepare("SELECT {$columns} FROM {$quotedTable} WHERE {$quotedKeys[0]} > :last_val ORDER BY {$order} LIMIT :limit"); $stmt->bindValue(':last_val', $lastRaw[0]); }
 else {
 $where=[]; for($i=0;$i<count($keys);$i++){ $cl=['(']; for($j=0;$j<$i;$j++) $cl[]="{$quotedKeys[$j]} = :eq_{$i}_{$j} AND "; $cl[]="{$quotedKeys[$i]} > :gt_{$i})"; $where[]=implode('',$cl); }
 $stmt=$pdo->prepare("SELECT {$columns} FROM {$quotedTable} WHERE (".implode(' OR ',$where).") ORDER BY {$order} LIMIT :limit");
 for($i=0;$i<count($keys);$i++){for($j=0;$j<$i;$j++)$stmt->bindValue(":eq_{$i}_{$j}",$lastRaw[$j]);$stmt->bindValue(":gt_{$i}",$lastRaw[$i]);}
 }
 } else {
 $fallbackOrder = (string)($tableState['fallback_order_by'] ?? '');
 if ($fallbackOrder === '') {
 // Eski/yarım kalmış state dosyalarında yedek yol sırası yoksa
 // bir kez üret ve hemen durum kaydına yaz. Aynı web zincirinde tekrar sorgulama.
 $fallbackOrder = get_table_fallback_order_by($pdo, $state['db_name'], $table);
 if ($fallbackOrder === '') {
 throw new Exception('WEB backup fallback sırası bulunamadı: ' . $table . '.');
 }
 $tableState['pagination_mode'] = 'ordered_offset_fallback';
 $tableState['fallback_order_by'] = $fallbackOrder;
 $state['web_table_state'] = $tableState;
 write_cli_job_state($backup_dir, $job_id, $state);
 }
 $stmt=$pdo->prepare("SELECT {$columns} FROM {$quotedTable} ORDER BY {$fallbackOrder} LIMIT :offset, :limit");
 $stmt->bindValue(':offset',$nextOffset,PDO::PARAM_INT);
 }
 $stmt->bindValue(':limit',$chunkSize,PDO::PARAM_INT); $stmt->execute(); $rows=[]; $rowsBytes=0; $lastRow=null; $chunkStarted=microtime(true); $yieldedByBudget=false; $hitRowLimit=false;
 while($row=$stmt->fetch(PDO::FETCH_ASSOC)){
 $lastRow=$row; $escapedRow='('.implode(',',array_map(fn($v)=>escape_string_safe($v,$pdo),$row)).')'; $rows[]=$escapedRow; $rowsBytes += strlen($escapedRow); $rowsExported++;
 if($rowsExported >= $chunkSize){ $hitRowLimit=true; break; }
 if($rowsBytes >= 2 * 1024 * 1024){ $hitRowLimit=true; break; }
 if((microtime(true)-$chunkStarted)>=2.5){ $yieldedByBudget=true; break; }
 }
 $stmt->closeCursor();
 if($rowsExported===0){$done=true;} else {
 write_web_backup_gzip_fragment($fragmentPath, static function($gz) use ($table,$columns,$rows):void{ $pos=0;$count=count($rows);while($pos<$count){$batch=array_slice($rows,$pos,250);safe_gzwrite($gz,"INSERT INTO `{$table}` ({$columns}) VALUES\n".implode(",\n",$batch).";\n");$pos+=count($batch);} });
 if($useKeyset){$raw=[];foreach($keys as $k)$raw[]=$lastRow[$k]??null;$nextLast=encode_web_cursor_values($raw);}else{$nextOffset += $rowsExported;}
 $done=(!$hitRowLimit && !$yieldedByBudget);
 }
 }
 } finally { if($locked){try{$pdo->exec('UNLOCK TABLES');}catch(Throwable $e){Logger::warning('Web backup READ LOCK bırakılamadı ['.$table.']: '.$e->getMessage());}} }

 if ($rowsExported === 0 && $done) {
 $tableState['done']=true; $state['web_table_state']=$tableState; write_cli_job_state($backup_dir,$job_id,$state); $index++; $state[$indexKey]=$index; $state['web_table_state']=[]; write_cli_job_state($backup_dir,$job_id,$state); $maxChunks--; continue;
 }

 $meta=['kind'=>'data','rows'=>$rowsExported,'next_chunk_index'=>$chunkIndex+1,'next_offset'=>$nextOffset,'next_last_values'=>$nextLast,'done'=>$done];
 if(!safe_file_put_contents($metaPath,json_encode($meta,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR),LOCK_EX)) throw new Exception('Web backup chunk metadata yazılamadı.');
 append_web_backup_fragment_idempotent($fragmentPath,$tmpFile);
 $processedRows += $rowsExported; $tableState['chunk_index']=$chunkIndex+1; $tableState['offset']=$nextOffset; $tableState['last_values']=$nextLast; $tableState['rows_for_table']=(int)($tableState['rows_for_table']??0)+$rowsExported; $tableState['done']=$done;
 $state['web_table_state']=$tableState; $state[$rowsKey]=$processedRows; $state[$indexKey]=$index; write_cli_job_state($backup_dir,$job_id,$state); @unlink($fragmentPath); @unlink($metaPath); heartbeat_web_worker_locks(); $maxChunks--;
 if($done){
 $index++;
 $state[$indexKey]=$index;
 $state['current_table_index'] = min($index + 1, count($tables));
 $state['current_table'] = $index < count($tables) ? (string)$tables[$index] : 'Tamamlandı';
 $state['web_table_state']=[];
 write_cli_job_state($backup_dir,$job_id,$state);
 }
 }

 if ($index < count($tables)) {
 $totalTables = count($tables);
 $elapsed = max(0.001, microtime(true) - (float)($state['job_started_at'] ?? microtime(true)));
 $currentIndexOneBased = $index + 1;
 // Yüzde tamamlanan tablo sayısını temsil eder; aktif tablo henüz tamamlanmadı.
 $percent = $totalTables > 0 ? min(99, (int)floor(($index / $totalTables) * 100)) : 0;
 $bytes = is_file($tmpFile) ? (int)filesize($tmpFile) : 0;
 $bytesPerSecond = $bytes / $elapsed;
 $eta = calculate_web_backup_eta($state, $currentIndexOneBased, $totalTables, $elapsed);
 $state['status']='running';
 $state['phase']='backup';
 $state['percent']=$percent;
 $state['total_tables']=$totalTables;
 $state['current_table_index']=$currentIndexOneBased;
 $state['current_table']=$index < $totalTables ? (string)$tables[$index] : 'Tamamlandı';
 $state['processed_rows']=$processedRows;
 $state['elapsed_seconds']=round($elapsed,2);
 $state['estimated_remaining_seconds']=$eta;
 $state['speed_rows_per_second']=(int)round($processedRows/$elapsed);
 $state['bytes_written']=$bytes;
 $state['formatted_bytes']=format_bytes($bytes);
 $state['speed_mb_per_second']=round($bytesPerSecond/1048576,2);
 $state['formatted_speed']=format_transfer_speed($bytesPerSecond);
 $state['message']=sprintf('%d/%d tablo tamamlandı. Aktif: %s.', $index, $totalTables, (string)$state['current_table']);
 if(!empty($state['is_emergency_backup'])){$state['emergency_percent']=$percent;$state['activity_tick']=(int)($state['activity_tick']??0)+1;}
 write_cli_job_state($backup_dir,$job_id,$state); return $state;
 }

 if(empty($state['objects_exported'])){
 $fragment=web_backup_static_fragment_path($fragmentDir,'999999_objects');
 if(!is_file($fragment)) write_web_backup_gzip_fragment($fragment,static function($gz)use($pdo,$state):void{export_database_objects_to_stream($pdo,$state['db_name'],$gz);safe_gzwrite($gz,"\nSET UNIQUE_CHECKS=1;\nSET FOREIGN_KEY_CHECKS=1;\n");});
 append_web_backup_fragment_idempotent($fragment,$tmpFile);$state['objects_exported']=true;write_cli_job_state($backup_dir,$job_id,$state);@unlink($fragment);
 }

 // Hard crash rename ile dosya doğrulama özeti arasına denk gelmişse hedef dosyayı yeniden doğrulayıp
 // mevcut işi tamamla; böylece geçerli yedek yetim/başarısız görünmez.
 if (!is_file($tmpFile) || (int)@filesize($tmpFile) <= 0) {
 if (!is_file($targetFile)) {
 throw new Exception('Web Worker final yedek geçici dosyası boş veya hedef dosya bulunamadı.');
 }
 $hash = verify_and_checksum_gzip($targetFile);
 } else {
 if (is_file($targetFile)) {
 try {
 $hash = verify_and_checksum_gzip($targetFile);
 @unlink($tmpFile);
 } catch (Throwable $existingTargetError) {
 @unlink($targetFile);
 @unlink($targetFile . '.sha256');
 if (!@rename($tmpFile, $targetFile)) {
 throw new Exception('Web Worker geçici gzip dosyası asıl hedefe taşınamadı: ' . $existingTargetError->getMessage());
 }
 $hash = verify_and_checksum_gzip($targetFile);
 }
 } else {
 if (!@rename($tmpFile, $targetFile)) throw new Exception('Web Worker geçici gzip dosyası hedef dosyaya taşınamadı.');
 $hash = verify_and_checksum_gzip($targetFile);
 }
 }
 $size=(int)@filesize($targetFile);$reservation=(string)($state['backup_reservation_file']??$state['reservation_file']??'');if($reservation!==''&&is_file($reservation))@unlink($reservation);if(empty($state['is_emergency_backup']))limit_backup_files($backup_dir,(int)$config['max_backups']);remove_web_backup_fragment_dir($fragmentDir);
 $duration=round(microtime(true)-(float)($state['job_started_at']??microtime(true)),2);$state['status']='completed';$state['phase']='completed';$state['percent']=100;$state['file']=basename($targetFile);$state['size']=$size;$state['bytes_written']=$size;$state['formatted_bytes']=format_bytes($size);$state['duration_seconds']=$duration;$state['estimated_remaining_seconds']=0;$state['sha256']=$hash;$state['current_table_index']=count($tables);$state['total_tables']=count($tables);$state['processed_rows']=$processedRows;$state['formatted_speed']=format_transfer_speed($duration > 0 ? ($size/$duration) : 0);
 if (!empty($state['is_emergency_backup'])) {
 $parentRestoreJobId = (string)($state['parent_restore_job_id'] ?? '');
 if (!preg_match('/^[a-f0-9]{32}$/', $parentRestoreJobId)) {
 throw new Exception('Emergency backup parent restore job ID geçersiz.');
 }
 write_web_emergency_completion_marker($backup_dir, $parentRestoreJobId, $job_id, basename($targetFile), $size, $hash);
 }
 write_cli_job_state($backup_dir,$job_id,$state);
 Logger::info(sprintf('WEB BACKUP BAŞARILI | job_id=%s | mode=per_table_read_lock_chunked | file=%s | tables=%d | rows=%d | size=%s | duration=%ss | sha256=%s',$job_id,basename($targetFile),count($tables),$processedRows,format_bytes($size),$duration,$hash));return $state;
}
function initialize_web_backup_job(PDO $pdo, string $backup_dir, array $config, string $job_id)
: array {
 $admissionLock = acquire_job_admission_lock($backup_dir);
 if (!$admissionLock) {
 throw new Exception('Başka bir backup/restore işlemi başlatılıyor. Lütfen tekrar deneyin.');
 }

 try {
 cleanup_stale_cli_job_states($backup_dir);
 assert_no_active_database_job($backup_dir, $job_id);
 check_sufficient_disk_space($pdo, $config['db_name'], $backup_dir);

 $tables = get_web_worker_tables($pdo, $config['db_name']);
 $paths = build_web_backup_paths($backup_dir, $config['db_name'], $job_id);
 $estimatedTotalRows = 0;
 try {
 $rowStmt = $pdo->prepare("SELECT COALESCE(SUM(TABLE_ROWS),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'");
 $rowStmt->execute([$config['db_name']]);
 $estimatedTotalRows = max(0, (int)($rowStmt->fetchColumn() ?? 0));
 $rowStmt->closeCursor();
 } catch (Throwable $rowEstimateError) {
 Logger::warning('Web backup toplam satır tahmini alınamadı: ' . $rowEstimateError->getMessage());
 }
 $now = microtime(true);

 $state = [
 'job_id' => $job_id,
 'engine' => 'web',
 'web_backup_protocol' => 2,
 'type' => 'backup',
 'status' => 'starting',
 'phase' => 'backup',
 'db_name' => $config['db_name'],
 'tables' => $tables,
 'total_tables' => count($tables),
 'current_table_index' => 0,
 'processed_rows' => 0,
 'estimated_total_rows' => $estimatedTotalRows,
 'current_table' => '',
 'backup_table_index' => 0,
 'backup_processed_rows' => 0,
 'backup_tables' => $tables,
 'backup_tmp_file' => $paths['tmp'],
 'backup_target_file' => $paths['target'],
 'backup_reservation_file' => $paths['reservation'],
 'fragment_dir' => $paths['tmp'] . '.parts',
 'backup_fragment_dir' => $paths['tmp'] . '.parts',
 'tmp_file' => $paths['tmp'],
 'target_file' => $paths['target'],
 'reservation_file' => $paths['reservation'],
 'job_started_at' => $now,
 'consistency_mode' => 'per_table_read_lock',
 'consistency_warning' => 'WEB modu veritabanı genelinde tek zamanlı snapshot garanti etmez. Tutarlı tam yedek için CLI modu kullanılmalıdır.',
 'sequences_exported' => false,
 'message' => 'Web Worker backup başlatıldı. Her tablo kendi export adımı içinde READ LOCK ile korunur; veritabanı genelinde tek snapshot garantisi yoktur.',
 'fallback_reason' => (string)($config['_web_fallback_reason'] ?? '')
 ];

 write_cli_job_state($backup_dir, $job_id, $state);

 Logger::warning(sprintf(
 'WEB WORKER BACKUP BAŞLATILDI | job_id=%s | mode=per_table_read_lock | reason=%s',
 $job_id,
 $state['fallback_reason'] !== '' ? $state['fallback_reason'] : 'Kullanıcı WEB çalışma modunu seçti.'
 ));

 return $state;
 } finally {
 release_job_admission_lock($admissionLock);
 }
}
function web_emergency_completion_marker_path(string $backup_dir, string $parent_job_id, string $emergency_job_id)
: string {
 if (!preg_match('/^[a-f0-9]{32}$/', $parent_job_id) || !preg_match('/^[a-f0-9]{32}$/', $emergency_job_id)) {
 throw new Exception('Geçersiz emergency completion marker job ID.');
 }
 return $backup_dir . '/.vedo_emergency_complete_' . $parent_job_id . '_' . $emergency_job_id . '.json';
}
function write_web_emergency_completion_marker(string $backup_dir, string $parent_job_id, string $emergency_job_id, string $file, int $size, string $sha256)
: void {
 if (!validate_backup_filename($file) || !is_emergency_backup_filename($file)) throw new Exception('Emergency completion marker için geçersiz dosya adı.');
 $sha256 = strtolower($sha256);
 if (!preg_match('/^[a-f0-9]{64}$/', $sha256)) throw new Exception('Emergency completion marker için geçersiz SHA256.');
 $path = web_emergency_completion_marker_path($backup_dir, $parent_job_id, $emergency_job_id);
 $marker = [
 'parent_restore_job_id' => $parent_job_id,
 'emergency_job_id' => $emergency_job_id,
 'status' => 'completed',
 'file' => $file,
 'size' => max(0, $size),
 'sha256' => $sha256,
 'completed_at' => time()
 ];
 $json = json_encode($marker, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
 $tmp = $path . '.tmp';
 if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
 @unlink($tmp);
 throw new Exception('Emergency completion marker atomik olarak yazılamadı.');
 }
}
function read_web_emergency_completion_marker(string $backup_dir, string $parent_job_id, string $emergency_job_id)
: array {
 $path = web_emergency_completion_marker_path($backup_dir, $parent_job_id, $emergency_job_id);
 if (!is_file($path)) return [];
 $raw = @file_get_contents($path);
 $data = is_string($raw) ? json_decode($raw, true) : null;
 if (!is_array($data)) return ['_invalid' => true, 'path' => $path];
 $file = (string)($data['file'] ?? '');
 if (($data['status'] ?? '') !== 'completed'
 || (string)($data['parent_restore_job_id'] ?? '') !== $parent_job_id
 || (string)($data['emergency_job_id'] ?? '') !== $emergency_job_id
 || !validate_backup_filename($file)
 || !is_emergency_backup_filename($file)
 || !preg_match('/^[a-f0-9]{64}$/', strtolower((string)($data['sha256'] ?? '')))) {
 return ['_invalid' => true, 'path' => $path];
 }
 return $data;
}
function delete_web_emergency_completion_marker(string $backup_dir, string $parent_job_id, string $emergency_job_id)
: void {
 try {
 $path = web_emergency_completion_marker_path($backup_dir, $parent_job_id, $emergency_job_id);
 @unlink($path);
 @unlink($path . '.tmp');
 } catch (Throwable $e) {
 Logger::warning('Emergency completion marker silinirken hata: ' . $e->getMessage());
 }
}

function initialize_web_emergency_backup_job(PDO $pdo, string $backup_dir, array $config, string $parent_job_id, int $existing_temp_bytes = 0)
: array {
 $emergencyJobId = bin2hex(random_bytes(16));
 check_sufficient_disk_space($pdo, $config['db_name'], $backup_dir, max(0, $existing_temp_bytes));
 $tables = get_web_worker_tables($pdo, $config['db_name']);
 $estimatedTotalRows = 0;
 try {
 $rowStmt = $pdo->prepare("SELECT COALESCE(SUM(TABLE_ROWS),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'");
 $rowStmt->execute([$config['db_name']]);
 $estimatedTotalRows = max(0, (int)($rowStmt->fetchColumn() ?? 0));
 $rowStmt->closeCursor();
 } catch (Throwable $rowEstimateError) {
 Logger::warning('Web emergency snapshot toplam satır tahmini alınamadı: ' . $rowEstimateError->getMessage());
 }
 $base = $backup_dir . '/.vedo_emergency_web_' . $parent_job_id . '_' . $emergencyJobId . '_' . gmdate('Y-m-d_H-i-s') . 'UTC';
 $target = $base . '.sql.gz';
 $tmp = $target . '.tmp';
 $reservation = $tmp . '.reserve';
 $fp = @fopen($reservation, 'x');
 if ($fp === false) throw new Exception('Web Worker emergency backup rezervasyonu oluşturulamadı.');
 fclose($fp);

 $state = [
 'job_id' => $emergencyJobId,
 'engine' => 'web',
 'web_backup_protocol' => 2,
 'type' => 'backup',
 'is_emergency_backup' => true,
 'parent_restore_job_id' => $parent_job_id,
 'completion_marker' => web_emergency_completion_marker_path($backup_dir, $parent_job_id, $emergencyJobId),
 'parent_acknowledged' => false,
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
 'backup_tmp_file' => $tmp,
 'backup_target_file' => $target,
 'backup_reservation_file' => $reservation,
 'fragment_dir' => $tmp . '.parts',
 'backup_fragment_dir' => $tmp . '.parts',
 'tmp_file' => $tmp,
 'target_file' => $target,
 'reservation_file' => $reservation,
 'job_started_at' => microtime(true),
 'consistency_mode' => 'per_table_read_lock_emergency',
 'sequences_exported' => false,
 'message' => 'Web Worker emergency snapshot: tablolar ayrı READ LOCK ile alınacak.'
 ];
 try {
 write_cli_job_state($backup_dir, $emergencyJobId, $state);
 } catch (Throwable $e) {
 @unlink($reservation);
 @unlink($tmp);
 @unlink($target);
 @unlink($target . '.sha256');
 @unlink($target . '.meta.json');
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json');
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json.tmp');
 throw $e;
 }
 Logger::warning(sprintf(
 'WEB RESTORE ÖNCESİ EMERGENCY SNAPSHOT BAŞLADI | parent_job=%s | emergency_job=%s | tables=%d',
 $parent_job_id, $emergencyJobId, count($tables)
 ));
 return $state;
}

function is_emergency_state_completed(array $state)
: bool {
 return !empty($state['is_emergency_backup']) && ($state['status'] ?? '') === 'completed' && !empty($state['file']);
}

/**
 * WEB geri yüklemede .sql.gz dosyasını küçük parçalar halinde açar. Her web isteği sınırlı bir iş yapar ve yarıda kalırsa geçici dosyadan kaldığı yere devam eder. Ayrı CLI işlemi kullanılmaz.
 */
function web_restore_temp_path_is_valid(string $path, string $job_id)
: bool {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) return false;
 if ($path === '') return false;

 $tmpDir = realpath(sys_get_temp_dir());
 $realPath = realpath($path);
 if (!$tmpDir || !$realPath) return false;
 if (!str_starts_with($realPath, $tmpDir . DIRECTORY_SEPARATOR)) return false;

 $base = basename($realPath);
 return str_starts_with($base, 'vedo_web_restore_' . $job_id . '_') && is_file($realPath);
}

function prepare_web_restore_stream_cache(string $sourcePath, string $job_id, string $backup_dir, array &$state)
: string {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) throw new Exception('Geçersiz Web Worker job ID.');
 if (!is_file($sourcePath) || !is_readable($sourcePath)) throw new Exception('Restore kaynak dosyası okunamıyor.');

 $prepareGeneration = (int)($state['prepare_stream_generation'] ?? 0);
 $prepareWorkerToken = (string)($state['prepare_stream_worker_token'] ?? '');
 if ($prepareGeneration <= 0 || !preg_match('/^[a-f0-9]{32}$/', $prepareWorkerToken)) {
 throw new Exception('__VEDO_PREP_STREAM_SUPERSEDED__');
 }

 $sourceSize = (int)@filesize($sourcePath);
 $sourceMtime = (int)@filemtime($sourcePath);
 if ($sourceSize <= 0) throw new Exception('Restore kaynak dosyası boş veya boyutu okunamıyor.');

 $expectedSourceSize = (int)($state['prepare_stream_source_size'] ?? 0);
 $expectedSourceMtime = (int)($state['prepare_stream_source_mtime'] ?? 0);
 if ($expectedSourceSize > 0 && $sourceSize !== $expectedSourceSize) {
 throw new Exception('WEB restore kaynağının boyutu hazırlama sırasında değişti.');
 }
 if ($expectedSourceMtime > 0 && $sourceMtime > 0 && $sourceMtime !== $expectedSourceMtime) {
 throw new Exception('WEB restore kaynağının değiştirilme zamanı hazırlama sırasında değişti.');
 }

 if ($expectedSourceSize <= 0 || $expectedSourceMtime <= 0) {
 $state['prepare_stream_source_size'] = $sourceSize;
 $state['prepare_stream_source_mtime'] = $sourceMtime;
 $expectedSourceSize = $sourceSize;
 $expectedSourceMtime = $sourceMtime;
 }

 $tmpDir = realpath(sys_get_temp_dir());
 if ($tmpDir === false || !is_dir($tmpDir) || !is_writable($tmpDir)) {
 throw new Exception('Web restore geçici çalışma dizini kullanılamıyor.');
 }

 $tmpPath = (string)($state['restore_stream_path'] ?? '');
 if ($tmpPath === '' || !web_restore_temp_path_is_valid($tmpPath, $job_id)) {
 $tmpSeed = @tempnam($tmpDir, 'vedo_web_restore_' . $job_id . '_');
 if ($tmpSeed === false) throw new Exception('Web restore geçici SQL stream dosyası oluşturulamadı.');
 $tmpPath = $tmpSeed . '.sql';
 if (!@rename($tmpSeed, $tmpPath)) {
 @unlink($tmpSeed);
 throw new Exception('Web restore geçici SQL stream dosyası hazırlanamadı.');
 }
 @chmod($tmpPath, 0600);
 $state['restore_stream_path'] = $tmpPath;
 $state['restore_stream_size'] = 0;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = time();
 $state['prepare_stream_source_offset'] = 0;
 }

 $actualWritten = (int)@filesize($tmpPath);
 if ($actualWritten < 0) $actualWritten = 0;
 // Gzip açılımı sıkıştırılmış kaynaktan yüzlerce kat büyük olabilir; sıkıştırma oranını
 // yapay bir 100x sınırıyla kesmek geçerli SQL dump'larını reddedebilir. Güvenli sınırlar
 // disk_free_space() kontrolü, kaynak boyut/dosya değişiklik zamanı sabitlemesi ve tamamlandığında ek bilgi
 // sağlamlık kontrolü üzerinden uygulanır.

 // Dosya yazıldıktan sonra state güncellenmeden HTTP isteği kesilmiş olabilir.
 // Bu durumda fiziksel geçici dosyası esas alınan kaynak kabul edilir ve state ileri alınır.
 $written = $actualWritten;
 $stateOffset = max(0, (int)($state['prepare_stream_source_offset'] ?? $state['prepare_stream_bytes_written'] ?? 0));
 if ($stateOffset !== $written) {
 $state['prepare_stream_source_offset'] = $written;
 $state['prepare_stream_bytes_written'] = $written;
 $state['restore_stream_size'] = $written;
 $state['restore_stream_ready'] = false;
 }

 // Web istekleri arasında gzip okuyucusunun iç bilgisi taşınamadığı için kaldığı yerden devam
 // Son yazılan açılmış konuma gzseek() ile gidilir. Dosyada ileri gitme işlemi her istekte yeniden
 // kurulmak zorunda olduğundan web isteği sayısını azaltmak için sınırlı/otomatik ayarlanan büyük
 // prepare dilimleri kullanılır.
 $gz = @gzopen($sourcePath, 'rb');
 $out = @fopen($tmpPath, 'ab');
 if (!$gz || !$out) {
 if ($gz) @gzclose($gz);
 if ($out) @fclose($out);
 throw new Exception('Web restore geçici SQL stream açılamadı.');
 }

 try {
 @set_time_limit(10);
 @ignore_user_abort(true);

 $seekStarted = microtime(true);
 if ($written > 0) {
 $seekResult = @gzseek($gz, $written, SEEK_SET);
 if ($seekResult !== 0) {
 throw new Exception('WEB restore gzip stream önceki konuma taşınamadı; resume güvenli değil.');
 }
 }
 $seekSeconds = microtime(true) - $seekStarted;

 // Web istekleri arasında gzip okuyucusunun iç bilgisi taşınamaz. Bu yüzden
 // kaldığı yerden devam için gzseek() gerekir. Bu işlemin maliyetini azaltmak için web isteği sayısını
 // büyütmemesi için her başarılı adım mümkün olduğunca büyük, ama sınırlı bir
 // dilimle devam eder. Son adımın throughput'u düşükse daha küçük limite geri iner.
 $lastStepSeconds = (float)($state['prepare_stream_last_step_seconds'] ?? 0);
 $lastStepBytes = max(0, (int)($state['prepare_stream_last_step_bytes'] ?? 0));
 $throughput = ($lastStepSeconds > 0 && $lastStepBytes > 0)
 ? ($lastStepBytes / $lastStepSeconds)
 : 0.0;
 $webPrepareBudget = get_dynamic_web_step_budget($tmpDir);
 $dynamicReadBytes = get_dynamic_restore_chunk_bytes($tmpDir);
 $adaptiveBytes = max(VEDO_WEB_RESTORE_PREP_SLICE_MIN_BYTES, min(VEDO_WEB_RESTORE_PREP_SLICE_MAX_BYTES, $dynamicReadBytes * max(4, (int)$webPrepareBudget['max_chunks'])));
 if ($throughput > 0) {
 $adaptiveBytes = (int)round($throughput * max(1.0, (float)$webPrepareBudget['max_step_seconds'] * 0.72));
 $adaptiveBytes = max(VEDO_WEB_RESTORE_PREP_SLICE_MIN_BYTES, min(VEDO_WEB_RESTORE_PREP_SLICE_MAX_BYTES, $adaptiveBytes));
 }
 if ($seekSeconds > 1.5) {
 $adaptiveBytes = min(VEDO_WEB_RESTORE_PREP_SLICE_MAX_BYTES, max($adaptiveBytes, $dynamicReadBytes * 8));
 }

 $sliceStarted = microtime(true);
 $sliceDeadline = $sliceStarted + max(0.75, min(VEDO_WEB_RESTORE_PREP_SLICE_SECONDS, (float)$webPrepareBudget['max_step_seconds']));
 $sliceBytes = 0;
 $completed = false;

 while (!gzeof($gz)) {
 if ($sliceBytes >= $adaptiveBytes) break;
 if (microtime(true) >= $sliceDeadline) break;

 $readSize = min(
 $dynamicReadBytes,
 $adaptiveBytes - $sliceBytes
 );
 $chunk = @gzread($gz, $readSize);
 if ($chunk === false) throw new Exception('Gzip veri stream okunamadı.');
 if ($chunk === '') {
 if (gzeof($gz)) {
 $completed = true;
 break;
 }
 continue;
 }

 $chunkLen = strlen($chunk);
 $free = @disk_free_space($tmpDir);
 if ($free === false || $free < $chunkLen + get_dynamic_disk_safety_bytes($tmpDir)) {
 throw new Exception('Web restore geçici SQL stream için yetersiz disk alanı.');
 }

 $offset = 0;
 while ($offset < $chunkLen) {
 $n = @fwrite($out, substr($chunk, $offset));
 if ($n === false || $n === 0) throw new Exception('Web restore geçici SQL stream yazılamadı.');
 $offset += $n;
 $written += $n;
 $sliceBytes += $n;
 }

 if (gzeof($gz)) {
 $completed = true;
 break;
 }
 }

 @fflush($out);
 $actualAfterWrite = (int)@filesize($tmpPath);
 if ($actualAfterWrite >= 0) $written = $actualAfterWrite;

 if (!$completed && gzeof($gz)) $completed = true;
 $state['prepare_stream_source_offset'] = $written;
 $state['prepare_stream_bytes_written'] = $written;
 $state['restore_stream_size'] = $written;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = (int)($state['restore_stream_created_at'] ?? time());
 $state['prepare_stream_last_step_seconds'] = round(microtime(true) - $sliceStarted, 3);
 $state['prepare_stream_last_step_bytes'] = $sliceBytes;
 $state['prepare_stream_last_seek_seconds'] = round($seekSeconds, 3);
 $state['prepare_stream_percent'] = 0;

 if ($completed) {
 $meta = json_encode([
 'job_id' => $job_id,
 'source' => basename($sourcePath),
 'size' => $written,
 'source_size' => $expectedSourceSize,
 'source_mtime' => $expectedSourceMtime,
 'created_at' => time()
 ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
 if (!safe_file_put_contents($tmpPath . '.meta', $meta)) {
 @unlink($tmpPath);
 @unlink($tmpPath . '.meta');
 throw new Exception('Web restore geçici stream metadata yazılamadı.');
 }
 @chmod($tmpPath . '.meta', 0600);
 $state['prepare_stream_completed'] = true;
 $state['prepare_stream_status'] = 'completed';
 $state['prepare_stream_pid'] = 0;
 $state['restore_stream_path'] = $tmpPath;
 $state['restore_stream_size'] = $written;
 $state['restore_stream_ready'] = true;
 $state['restore_stream_created_at'] = time();
 $state['message'] = 'WEB Worker restore stream hazır.';
 } else {
 $state['prepare_stream_completed'] = false;
 $state['prepare_stream_status'] = 'running';
 $state['prepare_stream_pid'] = 0;
 $state['message'] = 'WEB Worker restore stream hazırlanıyor... ' . format_bytes($written);
 }

 $persisted = update_cli_job_state_for_prepare_worker(
 $backup_dir,
 $job_id,
 $prepareWorkerToken,
 static function (array $current) use ($state, $tmpPath, $written, $completed): array {
 $current['prepare_stream_source_offset'] = $written;
 $current['prepare_stream_bytes_written'] = $written;
 $current['restore_stream_path'] = $tmpPath;
 $current['restore_stream_size'] = $written;
 $current['restore_stream_created_at'] = (int)($state['restore_stream_created_at'] ?? time());
 $current['prepare_stream_last_step_seconds'] = (float)($state['prepare_stream_last_step_seconds'] ?? 0);
 $current['prepare_stream_last_step_bytes'] = (int)($state['prepare_stream_last_step_bytes'] ?? 0);
 $current['prepare_stream_last_seek_seconds'] = (float)($state['prepare_stream_last_seek_seconds'] ?? 0);
 $current['prepare_stream_percent'] = (int)($state['prepare_stream_percent'] ?? 0);
 $current['prepare_stream_completed'] = $completed;
 $current['prepare_stream_status'] = $completed ? 'completed' : 'running';
 $current['prepare_stream_pid'] = 0;
 $current['status'] = $completed ? 'waiting' : 'waiting';
 $current['phase'] = 'prepare_stream';
 $current['restore_stream_ready'] = $completed;
 $current['message'] = (string)($state['message'] ?? 'WEB Worker restore stream hazırlanıyor...');
 return $current;
 }
 );
 if (!$persisted) throw new Exception('__VEDO_PREP_STREAM_SUPERSEDED__');
 $state = read_cli_job_state($backup_dir, $job_id) ?: $state;
 } catch (Throwable $e) {
 // web isteği kesintisi sırasında fiziksel geçici baş kısmını koru; sonraki durumu tekrar sorma dosya boyundan kaldığı yerden devam eder.
 if ($e->getMessage() === '__VEDO_PREP_STREAM_SUPERSEDED__') {
 @fclose($out);
 @gzclose($gz);
 throw $e;
 }
 $state['prepare_stream_status'] = 'failed';
 $state['prepare_stream_pid'] = 0;
 $state['restore_stream_size'] = (int)@filesize($tmpPath);
 $state['prepare_stream_source_offset'] = max(0, (int)$state['restore_stream_size']);
 $state['prepare_stream_bytes_written'] = $state['prepare_stream_source_offset'];
 $state['restore_stream_ready'] = false;
 throw $e;
 } finally {
 @fclose($out);
 @gzclose($gz);
 }

 return $tmpPath;
}
function cleanup_web_restore_stream_cache(array $state)
: void {
 $path = (string)($state['restore_stream_path'] ?? '');
 $jobId = (string)($state['job_id'] ?? '');
 if ($path === '' || !web_restore_temp_path_is_valid($path, $jobId)) return;

 $realPath = realpath($path);
 if ($realPath !== false) {
 @unlink($realPath);
 @unlink($realPath . '.meta');
 }
}

function cleanup_orphan_web_restore_temp_files(string $backup_dir, int $max_age = 3600)
: void {
 $tmpDir = realpath(sys_get_temp_dir());
 if (!$tmpDir || !is_dir($tmpDir)) return;

 $now = time();
 $referenced = [];
 foreach (glob($backup_dir . '/.cli_job_*.json') ?: [] as $statePath) {
 if (!is_file($statePath)) continue;
 $data = json_decode((string)@file_get_contents($statePath), true);
 if (!is_array($data)) continue;
 $jobId = (string)($data['job_id'] ?? '');
 $path = (string)($data['restore_stream_path'] ?? '');
 if ($jobId !== '' && web_restore_temp_path_is_valid($path, $jobId)) {
 $referenced[realpath($path) ?: $path] = true;
 }
 }

 foreach (glob($tmpDir . '/vedo_web_restore_*.sql') ?: [] as $path) {
 if (!is_file($path)) continue;
 $base = basename($path);
 if (!preg_match('/^vedo_web_restore_[a-f0-9]{32}_[A-Za-z0-9]+\.sql$/', $base)) continue;
 $mtime = (int)@filemtime($path);
 $age = $mtime > 0 ? max(0, $now - $mtime) : ($max_age + 1);
 $real = realpath($path) ?: $path;
 if (!isset($referenced[$real]) && $age > $max_age) {
 @unlink($path);
 @unlink($path . '.meta');
 }
 }
 foreach (glob($tmpDir . '/vedo_web_restore_*.sql.meta') ?: [] as $meta) {
 if (!is_file($meta)) continue;
 $sqlPath = substr($meta, 0, -5);
 if (!is_file($sqlPath)) {
 $mtime = (int)@filemtime($meta);
 $age = $mtime > 0 ? max(0, $now - $mtime) : ($max_age + 1);
 if ($age > $max_age) @unlink($meta);
 }
 }
}

// WEB işçi süreci geri yükleme işini parça parça çalıştırır; önce veri tabanı durumunu kontrol eder ve gerekiyorsa temizler.
/**
 * WEB geri yükleme durum makinesinin tek adımını çalıştırır. Kaynak kontrol, acil durum yedeği,
 * veri tabanı temizliği, SQL aktarımı ve son ANALYZE aşamalarını sırayla yönetir.
 */
function web_restore_commit_marker_path(string $backup_dir, string $job_id)
: string {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) throw new Exception('Geçersiz Web Worker job ID.');
 return $backup_dir . '/.web_restore_commit_' . $job_id . '.json';
}

function read_web_restore_commit_marker(string $backup_dir, string $job_id)
: array {
 $path = web_restore_commit_marker_path($backup_dir, $job_id);
 if (!is_file($path)) return [];
 $data = json_decode((string)@file_get_contents($path), true);
 return is_array($data) ? $data : [];
}

function write_web_restore_commit_marker(string $backup_dir, string $job_id, array $marker)
: void {
 $path = web_restore_commit_marker_path($backup_dir, $job_id);
 $tmp = $path . '.tmp';
 $marker['job_id'] = $job_id;
 $marker['committed_at'] = time();
 $json = json_encode($marker, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
 if (!safe_file_put_contents($tmp, $json) || !@rename($tmp, $path)) {
 @unlink($tmp);
 throw new Exception('Web restore commit marker yazılamadı.');
 }
}

function delete_web_restore_commit_marker(string $backup_dir, string $job_id)
: void {
 try {
 $path = web_restore_commit_marker_path($backup_dir, $job_id);
 @unlink($path);
 @unlink($path . '.tmp');
 } catch (Throwable $e) {
 Logger::warning('Web restore commit marker silinirken hata: ' . $e->getMessage());
 }
}

function web_restore_state_needs_stale_recovery(array $state)
: bool {
 if (($state['engine'] ?? '') !== 'web' || ($state['type'] ?? '') !== 'restore') return false;
 if (!empty($state['recovery_mode']) || !empty($state['restore_verified'])) return false;
 if (empty($state['emergency_backup_completed']) || (string)($state['emergency_file'] ?? '') === '') return false;
 if (!in_array((string)($state['phase'] ?? ''), ['clear_database', 'prepare_stream', 'preflight_stream', 'restore'], true)) return false;

 // Veri tabanında geri çevrilemeyen bir işlem durum kaydında devam ediyor olarak
 // işaretlendiyse beklemeye gerek yok. Çalışan işlem kapanırsa aynı SQL’i tekrar çalıştırmak yerine
 // acil yedek kurtarma tercih edilir.
 if (!empty($state['destructive_operation_in_progress']) || !empty($state['query_in_progress'])) {
 return true;
 }

 $updatedAt = (int)($state['updated_at'] ?? 0);
 return $updatedAt > 0 && (time() - $updatedAt) >= VEDO_WEB_RESTORE_STALE_RECOVERY_SECONDS;
}


// =============================================================================
// PHP - WEB TABANLI GERİ YÜKLEME İŞÇİSİ
// Büyük geri yükleme işlemini küçük HTTP adımlarına böler ve her adımın durumunu
// dosyalarda saklayarak tarayıcıya ilerleme bilgisi verir.
// =============================================================================

function web_restore_step(PDO $pdo, string $job_id, string $backup_dir, array $config)
: array {
 $state = read_cli_job_state($backup_dir, $job_id);
 if (!$state || ($state['engine'] ?? '') !== 'web' || ($state['type'] ?? '') !== 'restore') {
 throw new Exception('Web Worker restore durumu bulunamadı.');
 }

 $file = (string)($state['file'] ?? '');
 if (!validate_backup_filename($file)) throw new Exception('Geçersiz Web Worker restore dosyası.');
 $safePath = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
 if (!is_file($safePath)) throw new Exception('Restore dosyası bulunamadı.');

 $phase = (string)($state['phase'] ?? 'verify_source');
 $recoveryMode = !empty($state['recovery_mode']);

 if ($phase === 'restore' && empty($state['restore_verified'])) {
 $commitMarker = read_web_restore_commit_marker($backup_dir, $job_id);
 if ($commitMarker !== []) {
 $markerFile = (string)($commitMarker['file'] ?? '');
 $markerHash = strtolower((string)($commitMarker['backup_sha256'] ?? ''));
 $stateHash = strtolower((string)($state['backup_sha256'] ?? ''));
 if ($markerFile !== '' && validate_backup_filename($markerFile)
 && preg_match('/^[a-f0-9]{64}$/', $markerHash)
 && ($stateHash === '' || hash_equals($stateHash, $markerHash))) {
 $markerRecoveryMode = !empty($commitMarker['recovery_mode']);
 $state['restore_verified'] = true;
 $state['source_verified'] = true;
 $state['backup_sha256'] = $markerHash;
 $state['processed_bytes'] = (int)($commitMarker['processed_bytes'] ?? $state['processed_bytes'] ?? 0);
 $state['restore_progress_size'] = (int)($commitMarker['restore_progress_size'] ?? $state['restore_progress_size'] ?? 0);
 $state['integrity'] = is_array($commitMarker['integrity'] ?? null) ? $commitMarker['integrity'] : [];

 $markerEmergency = (string)($commitMarker['emergency_file'] ?? $state['emergency_file'] ?? '');
 if ($markerEmergency !== '' && validate_backup_filename($markerEmergency) && is_emergency_backup_filename($markerEmergency)) {
 cleanup_emergency_backup_artifacts($backup_dir, $markerEmergency);
 }
 $markerEmergencyJobId = (string)($state['emergency_job_id'] ?? '');
 if (preg_match('/^[a-f0-9]{32}$/', $markerEmergencyJobId)) {
 @unlink($backup_dir . '/.cli_job_' . $markerEmergencyJobId . '.json');
 @unlink($backup_dir . '/.cli_job_' . $markerEmergencyJobId . '.json.tmp');
 }
 cleanup_web_restore_stream_cache($state);
 $state['restore_stream_path'] = '';
 $state['restore_stream_size'] = 0;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = 0;
 $state['emergency_file'] = '';
 $state['emergency_backup_completed'] = false;
 $state['file'] = $markerRecoveryMode
 ? (string)($state['original_restore_file'] ?? $markerFile)
 : $markerFile;

 if (!$markerRecoveryMode && !$recoveryMode && (bool)$config['analyze_after_restore']) {
 $state['status'] = 'waiting';
 $state['phase'] = 'analyze';
 $state['analyze_engine'] = 'web';
 $state['percent'] = 99;
 $state['analyze_index'] = 0;
 $state['analyze_tables'] = get_web_worker_tables($pdo, $config['db_name']);
 $state['analyze_total'] = count($state['analyze_tables']);
 $state['analyze_successful'] = 0;
 $state['analyze_failed'] = 0;
 $state['analyze_warnings'] = [];
 $state['analyze_started_at'] = microtime(true);
 $state['analyze_current_table'] = $state['analyze_tables'][0] ?? 'Yok';
 $state['analyze_elapsed_seconds'] = 0.0;
 $state['analyze_last_step_seconds'] = 0.0;
 $state['analyze_in_progress'] = false;
 $state['analyze_running_table'] = '';
 $state['current_table'] = $state['analyze_current_table'];
 $state['message'] = 'Restore tamamlandı. Web Worker ANALYZE için hazır.';
 } else {
 $state['status'] = 'completed';
 $state['phase'] = 'completed';
 $state['percent'] = 100;
 $state['recovered'] = $markerRecoveryMode ? true : (bool)($state['recovered'] ?? false);
 $state['current_table'] = 'Tamamlandı';
 $state['message'] = $markerRecoveryMode
 ? 'Recovery başarıyla tamamlandı; eski veritabanı geri yüklendi.'
 : 'Restore başarıyla tamamlandı.';
 }
 write_cli_job_state($backup_dir, $job_id, $state);
 if (($state['phase'] ?? '') === 'completed') {
 end_restore_maintenance($backup_dir, $job_id);
 }
 delete_web_restore_commit_marker($backup_dir, $job_id);
 return $state;
 }
 Logger::warning('WEB RESTORE COMMIT MARKER state ile eşleşmedi; marker kullanılmayacak | job_id=' . $job_id);
 }
 }

 // WEB GERİ YÜKLEME KAYNAK DOĞRULAMASI
 // SHA-256 kontrol durumu durumu tekrar sorma istekleri arasında korunur.
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
 $hashCtx = unserialize(base64_decode($verifyCtxEncoded, true), ['allowed_classes' => [HashContext::class]]);
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
 $chunkBytes = 1024 * 1024; // Her adımda en fazla 1 MB oku.
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
 heartbeat_web_worker_locks();
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

 // Gzip başlığı ve akışı açılabiliyor mu diye doğrula. Geri yükleme motorunun
 // kendisi dosyanın tamamını okuyacağı için veri akışı bütünlüğü de geri yükleme
 // sırasında kesin olarak kontrol edilir; burada en azından kaynağın
 // geçerli bir gzip olarak açılabildiğini geri yükleme öncesinde teyit ederiz.
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
 $state['preflight_verified'] = false;
 $state['preflight_queries_validated'] = 0;
 $state['preflight_offset'] = 0;
 $state['preflight_file_size'] = 0;
 $state['preflight_query_buffer'] = '';
 $state['preflight_in_string'] = false;
 $state['preflight_string_char'] = '';
 $state['preflight_in_comment_multi'] = false;
 $state['preflight_in_comment_single'] = false;
 $state['preflight_escaped'] = false;
 $state['preflight_current_delimiter'] = ';';
 $state['preflight_delimiter_line_buffer'] = '';
 $state['phase'] = 'prepare_stream';
 $state['status'] = 'waiting';
 $state['percent'] = 0;
 $state['current_table'] = 'Restore stream hazırlanıyor';
 $state['message'] = 'Restore kaynağı doğrulandı. SQL stream hazırlanacak ve güvenlik/uyumluluk kontrolü parça parça yapılacak.';

 Logger::info(sprintf(
 'WEB RESTORE KAYNAK DOĞRULANDI | job_id=%s | file=%s | sha256=%s | bytes=%d | preflight=deferred',
 $job_id,
 $file,
 $currentHash,
 $fileSize
 ));
 }

 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 // GERİ YÜKLEME ÖNCESİ ACİL DURUM ANLIK GÖRÜNTÜSÜ
 if ($phase === 'emergency_backup') {
 $emergencyJobId = (string)($state['emergency_job_id'] ?? '');
 if (!preg_match('/^[a-f0-9]{32}$/', $emergencyJobId)) {
 throw new Exception('Web emergency backup job ID geçersiz.');
 }

 $completionMarker = read_web_emergency_completion_marker($backup_dir, $job_id, $emergencyJobId);
 if (!empty($completionMarker['_invalid'])) {
 throw new Exception('Web emergency completion marker bozuk. Güvenlik nedeniyle recovery durduruldu.');
 }
 $emergencyState = read_cli_job_state($backup_dir, $emergencyJobId);
 if ($completionMarker !== []) {
 $emergencyState = is_array($emergencyState) ? $emergencyState : [];
 $emergencyState['is_emergency_backup'] = true;
 $emergencyState['status'] = 'completed';
 $emergencyState['file'] = (string)$completionMarker['file'];
 }
 if (!$emergencyState || empty($emergencyState['is_emergency_backup'])) {
 throw new Exception('Web emergency backup durumu bulunamadı.');
 }

 if (($emergencyState['status'] ?? '') === 'failed') {
 $reservationFile = (string)($emergencyState['backup_reservation_file'] ?? $emergencyState['reservation_file'] ?? '');
 if ($reservationFile !== '' && is_file($reservationFile)) @unlink($reservationFile);
 throw new Exception('Web emergency snapshot başarısız: ' . (string)($emergencyState['error'] ?? 'Bilinmeyen hata'));
 }

 if (is_emergency_state_completed($emergencyState)) {
 $emergencyFile = (string)$emergencyState['file'];
 if (!validate_backup_filename($emergencyFile) || !is_emergency_backup_filename($emergencyFile)) {
 throw new Exception('Web emergency backup dosya adı geçersiz.');
 }
 $emergencyPath = validate_path_safe($backup_dir . '/' . $emergencyFile, $backup_dir);
 if (!is_file($emergencyPath)) throw new Exception('Web emergency backup dosyası bulunamadı.');
 $emergencyHash = verify_backup_checksum($emergencyPath);
 if ($completionMarker !== []) {
 $markerHash = strtolower((string)($completionMarker['sha256'] ?? ''));
 $markerSize = (int)($completionMarker['size'] ?? 0);
 if (!hash_equals($markerHash, strtolower($emergencyHash)) || ($markerSize > 0 && $markerSize !== (int)filesize($emergencyPath))) {
 throw new Exception('Emergency completion marker ile gerçek dosya bütünlüğü eşleşmiyor.');
 }
 }

 $state['emergency_file'] = $emergencyFile;
 $state['emergency_backup_completed'] = true;
 $state['phase'] = 'clear_database';
 $state['status'] = 'clearing';
 $state['percent'] = 0;
 $state['current_table'] = 'Veritabanına format atılıyor';
 $state['message'] = 'Web emergency snapshot tamamlandı. Mevcut veritabanı şimdi temizlenecek.';
 Logger::warning(sprintf(
 'WEB RESTORE ÖNCESİ EMERGENCY SNAPSHOT TAMAMLANDI | parent_job=%s | emergency_job=%s | file=%s',
 $job_id, $emergencyJobId, $emergencyFile
 ));
 write_cli_job_state($backup_dir, $job_id, $state);
 $ackState = read_cli_job_state($backup_dir, $emergencyJobId);
 if (is_array($ackState) && !empty($ackState['is_emergency_backup'])) {
 $ackState['parent_acknowledged'] = true;
 write_cli_job_state($backup_dir, $emergencyJobId, $ackState);
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json');
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json.tmp');
 delete_web_emergency_completion_marker($backup_dir, $job_id, $emergencyJobId);
 } else {
 delete_web_emergency_completion_marker($backup_dir, $job_id, $emergencyJobId);
 }
 return $state;
 }

 $emergencyPercent = max(0, min(99, (int)($emergencyState['percent'] ?? $emergencyState['emergency_percent'] ?? 0)));
 $state['status'] = 'waiting';
 // acil yedek'ın gerçek ilerlemesini ana Web arka plan işlem adımı durumuna aynen aktar.
 // Aksi halde arayüz ana iş durumundaki eski 0 satır / %0 değerini göstermeye devam eder.
 $state['percent'] = $emergencyPercent;
 $state['emergency_percent'] = $emergencyPercent;
 $state['current_table'] = (string)($emergencyState['current_table'] ?? 'Emergency snapshot hazırlanıyor');
 $state['current_table_index'] = (int)($emergencyState['current_table_index'] ?? 0);
 $state['total_tables'] = (int)($emergencyState['total_tables'] ?? 0);
 $state['processed_rows'] = (int)($emergencyState['processed_rows'] ?? 0);
 $state['elapsed_seconds'] = (float)($emergencyState['elapsed_seconds'] ?? 0);
 $state['speed_rows_per_second'] = (int)($emergencyState['speed_rows_per_second'] ?? 0);
 $state['bytes_written'] = (int)($emergencyState['bytes_written'] ?? 0);
 $state['formatted_bytes'] = (string)($emergencyState['formatted_bytes'] ?? '0 B');
 $state['speed_mb_per_second'] = (float)($emergencyState['speed_mb_per_second'] ?? 0);
 $state['emergency_activity_tick'] = (int)($state['emergency_activity_tick'] ?? 0) + 1;
 $state['message'] = (string)($emergencyState['message'] ?? 'Web emergency snapshot devam ediyor.');
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 if ($phase === 'prepare_stream') {
 // WEB hazırlık işi artık tamamen HTTP/Web arka plan işlem adımı içinde ve zaman dilimlidir.
 // Yarıda kesilen web isteği, geçici SQL dosyasının gerçek boyutundan kaldığı yerden devam eder.
 if (($state['prepare_stream_status'] ?? '') === 'failed') {
 $existingFailedPath = (string)($state['restore_stream_path'] ?? '');
 $existingFailedSize = (int)($state['restore_stream_size'] ?? 0);
 if (!empty($state['restore_stream_ready'])
 && $existingFailedSize > 0
 && web_restore_temp_path_is_valid($existingFailedPath, $job_id)) {
 $state['prepare_stream_completed'] = true;
 $state['prepare_stream_status'] = 'completed';
 $state['prepare_stream_pid'] = 0;
 $state['status'] = 'waiting';
 $state['current_table'] = 'Restore stream hazır';
 $state['message'] = 'Restore stream daha önce başarıyla oluşturuldu; yeniden kullanılacak.';
 write_cli_job_state($backup_dir, $job_id, $state);
 } else {
 $streamError = trim((string)($state['error'] ?? ''));
 throw new Exception($streamError !== '' ? $streamError : 'WEB restore stream hazırlanamadı.');
 }
 }

 $state['status'] = 'waiting';
 $state['current_table'] = 'Restore stream hazırlanıyor';

 if (!empty($state['prepare_stream_completed']) && !empty($state['restore_stream_ready'])) {
 $streamSize = (int)($state['restore_stream_size'] ?? 0);
 if ($streamSize <= 0 || !web_restore_temp_path_is_valid((string)($state['restore_stream_path'] ?? ''), $job_id)) {
 throw new Exception('Hazır restore stream dosyası doğrulanamadı.');
 }
 $state['preflight_offset'] = 0;
 $state['preflight_file_size'] = $streamSize;
 $state['preflight_query_buffer'] = '';
 $state['preflight_in_string'] = false;
 $state['preflight_string_char'] = '';
 $state['preflight_in_comment_multi'] = false;
 $state['preflight_in_comment_single'] = false;
 $state['preflight_escaped'] = false;
 $state['preflight_current_delimiter'] = ';';
 $state['preflight_delimiter_line_buffer'] = '';
 $state['preflight_queries_validated'] = 0;
 $state['preflight_verified'] = false;
 $state['preflight_source_verified'] = false;
 $state['restore_progress_size'] = $streamSize;
 $state['phase'] = 'preflight_stream';
 $state['status'] = 'running';
 $state['percent'] = 0;
 $state['message'] = 'Restore SQL güvenlik/uyumluluk kontrolü parça parça yapılıyor...';
 $state['current_table'] = 'Restore SQL doğrulanıyor';
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 $fileSize = (int)@filesize($safePath);
 $fileMtime = (int)@filemtime($safePath);
 if ($fileSize <= 0) throw new Exception('WEB restore kaynak dosyasının boyutu okunamadı.');
 if (!empty($state['prepare_stream_source_size']) && (int)$state['prepare_stream_source_size'] !== $fileSize) {
 throw new Exception('WEB restore kaynak dosyasının boyutu hazırlama sırasında değişti.');
 }
 if (!empty($state['prepare_stream_source_mtime']) && $fileMtime > 0 && (int)$state['prepare_stream_source_mtime'] !== $fileMtime) {
 throw new Exception('WEB restore kaynak dosyası hazırlama sırasında değişti.');
 }

 $workerToken = (string)($state['prepare_stream_worker_token'] ?? '');
 if (!preg_match('/^[a-f0-9]{32}$/', $workerToken)) {
 $state['prepare_stream_generation'] = (int)($state['prepare_stream_generation'] ?? 0) + 1;
 $state['prepare_stream_worker_token'] = bin2hex(random_bytes(16));
 $state['prepare_stream_status'] = 'running';
 $state['prepare_stream_pid'] = 0;
 $state['prepare_stream_started_at'] = time();
 $state['prepare_stream_percent'] = 0;
 $state['prepare_stream_bytes_written'] = 0;
 $state['prepare_stream_source_offset'] = 0;
 $state['prepare_stream_source_size'] = $fileSize;
 $state['prepare_stream_source_mtime'] = $fileMtime;
 $state['prepare_stream_last_step_seconds'] = 0.0;
 $state['prepare_stream_last_step_bytes'] = 0;
 $state['prepare_stream_last_seek_seconds'] = 0.0;
 $state['status'] = 'running';
 $state['current_table'] = 'Restore stream hazırlanıyor';
 $state['message'] = 'WEB Worker restore stream hazırlanıyor...';
 write_cli_job_state($backup_dir, $job_id, $state);
 } else {
 $state['prepare_stream_status'] = 'running';
 $state['prepare_stream_pid'] = 0;
 $state['status'] = 'running';
 $state['current_table'] = 'Restore stream hazırlanıyor';
 }

 try {
 prepare_web_restore_stream_cache($safePath, $job_id, $backup_dir, $state);
 $state = read_cli_job_state($backup_dir, $job_id) ?: $state;
 $streamSize = (int)($state['restore_stream_size'] ?? 0);
 if (empty($state['prepare_stream_completed'])) {
 $state['status'] = 'waiting';
 $state['phase'] = 'prepare_stream';
 $state['percent'] = 0;
 $state['current_table'] = 'Restore stream hazırlanıyor';
 $state['message'] = (string)($state['message'] ?? 'WEB Worker restore stream hazırlanıyor...');
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }
 if ($streamSize <= 0) throw new Exception('Restore stream hazırlandı ancak boş görünüyor.');
 } catch (Throwable $e) {
 $state = read_cli_job_state($backup_dir, $job_id) ?: $state;
 // Web web isteği'in dış zaman aşımı ile öldürülmesi catch'e düşmeyebilir; normal hatada geçici baş kısmını temizleme.
 $state['prepare_stream_status'] = 'failed';
 $state['prepare_stream_pid'] = 0;
 $state['status'] = 'failed';
 $state['phase'] = 'prepare_stream';
 $state['error'] = $e->getMessage();
 $state['message'] = $e->getMessage();
 if ($e->getMessage() !== '__VEDO_PREP_STREAM_SUPERSEDED__') {
 $state['restore_stream_ready'] = false;
 write_cli_job_state($backup_dir, $job_id, $state);
 }
 throw $e;
 }

 $state['prepare_stream_completed'] = true;
 $state['prepare_stream_status'] = 'completed';
 $state['prepare_stream_pid'] = 0;
 $state['preflight_offset'] = 0;
 $state['preflight_file_size'] = $streamSize;
 $state['preflight_query_buffer'] = '';
 $state['preflight_in_string'] = false;
 $state['preflight_string_char'] = '';
 $state['preflight_in_comment_multi'] = false;
 $state['preflight_in_comment_single'] = false;
 $state['preflight_escaped'] = false;
 $state['preflight_current_delimiter'] = ';';
 $state['preflight_delimiter_line_buffer'] = '';
 $state['preflight_pending_boundary'] = '';
 $state['preflight_queries_validated'] = 0;
 $state['preflight_verified'] = false;
 $state['restore_progress_size'] = $streamSize;
 $state['phase'] = 'preflight_stream';
 $state['status'] = 'running';
 $state['percent'] = 0;
 $state['message'] = 'Restore SQL güvenlik/uyumluluk kontrolü parça parça yapılıyor...';
 $state['current_table'] = 'Restore SQL doğrulanıyor';
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 if ($phase === 'preflight_stream') {
 if (empty($state['preflight_source_verified'])) {
 $sourceSize = (int)@filesize($safePath);
 $expectedSourceSize = (int)($state['source_file_size'] ?? $state['file_size'] ?? 0);
 if ($expectedSourceSize > 0 && $sourceSize !== $expectedSourceSize) {
 throw new Exception('Restore kaynak dosyasının boyutu preflight başlamadan önce değişti.');
 }
 $expectedSourceHash = strtolower((string)($state['backup_sha256'] ?? ''));
 if ($expectedSourceHash !== '' && preg_match('/^[a-f0-9]{64}$/', $expectedSourceHash)) {
 $currentSourceHash = strtolower(verify_backup_checksum($safePath));
 if (!hash_equals($expectedSourceHash, $currentSourceHash)) {
 throw new Exception('Restore kaynak checksum değeri preflight başlamadan önce değişti.');
 }
 }
 $state['preflight_source_verified'] = true;
 }
 $streamPath = (string)($state['restore_stream_path'] ?? '');
 $streamSize = (int)($state['restore_stream_size'] ?? $state['preflight_file_size'] ?? 0);
 if (empty($state['restore_stream_ready'])) {
 throw new Exception('Restore SQL stream henüz hazır değil.');
 }
 if ($streamPath === '' || !web_restore_temp_path_is_valid($streamPath, $job_id) || !is_readable($streamPath)) {
 throw new Exception('Restore SQL stream dosyası kullanılamıyor.');
 }
 if ($streamSize <= 0) {
 throw new Exception('Restore SQL stream boyutu geçersiz.');
 }

 $offset = (int)($state['preflight_offset'] ?? 0);
 if ($offset < 0 || $offset > $streamSize) {
 throw new Exception('WEB restore preflight konumu geçersiz.');
 }

 $queryBuffer = (string)($state['preflight_query_buffer'] ?? '');
 $inString = !empty($state['preflight_in_string']);
 $stringChar = (string)($state['preflight_string_char'] ?? '');
 $inCommentMulti = !empty($state['preflight_in_comment_multi']);
 $inCommentSingle = !empty($state['preflight_in_comment_single']);
 $escaped = !empty($state['preflight_escaped']);
 $currentDelimiter = (string)($state['preflight_current_delimiter'] ?? ';');
 $delimiterLineBuffer = (string)($state['preflight_delimiter_line_buffer'] ?? '');
 $pendingBoundary = (string)($state['preflight_pending_boundary'] ?? '');
 $queryCount = (int)($state['preflight_queries_validated'] ?? 0);

 $fp = @fopen($streamPath, 'rb');
 if ($fp === false) throw new Exception('Restore SQL stream preflight için açılamadı.');

 $startedAt = microtime(true);
 $webBudget = get_dynamic_web_step_budget($backup_dir);
 $maxStepSeconds = (float)$webBudget['max_step_seconds'];
 $chunkBytes = get_dynamic_restore_chunk_bytes($backup_dir);
 $eof = false;
 try {
 if ($offset > 0 && fseek($fp, $offset, SEEK_SET) !== 0) {
 throw new Exception('Restore SQL stream preflight konumuna gidilemedi.');
 }

 while ($offset < $streamSize && (microtime(true) - $startedAt) < $maxStepSeconds) {
 $readLen = min($chunkBytes, $streamSize - $offset);
 $rawChunk = fread($fp, $readLen);
 if ($rawChunk === false) throw new Exception('Restore SQL stream preflight sırasında okunamadı.');
 if ($rawChunk === '') throw new Exception('Restore SQL stream preflight sırasında beklenmeyen EOF oluştu.');
 $offset += strlen($rawChunk);

 $queries = restore_parse_buffer(
 $rawChunk,
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );

 foreach ($queries as $query) {
 validate_restore_sql_statement($query, true, (string)($config['db_name'] ?? ''));
 $queryCount++;
 }
 }
 $eof = ($offset >= $streamSize);
 } finally {
 fclose($fp);
 }

 if ($eof) {
 if ($delimiterLineBuffer !== '' && preg_match('/^\s*DELIMITER(?:[ \t]+[^\r\n]*)?$/i', $delimiterLineBuffer) && !$inString && !$inCommentMulti && !$inCommentSingle) {
 $queries = restore_parse_buffer(
 "\n",
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );
 foreach ($queries as $query) {
 validate_restore_sql_statement($query, true, (string)($config['db_name'] ?? ''));
 $queryCount++;
 }
 }

 $finalQuery = finalize_restore_parser(
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );
 if ($finalQuery !== null) {
 validate_restore_sql_statement($finalQuery, true, (string)($config['db_name'] ?? ''));
 $queryCount++;
 }

 $state['preflight_offset'] = $streamSize;
 $state['preflight_file_size'] = $streamSize;
 $state['preflight_queries_validated'] = $queryCount;
 $state['preflight_query_buffer'] = '';
 $state['preflight_in_string'] = false;
 $state['preflight_string_char'] = '';
 $state['preflight_in_comment_multi'] = false;
 $state['preflight_in_comment_single'] = false;
 $state['preflight_escaped'] = false;
 $state['preflight_current_delimiter'] = ';';
 $state['preflight_delimiter_line_buffer'] = '';
 $state['preflight_pending_boundary'] = '';
 $state['preflight_verified'] = true;
 $state['preflight_source_verified'] = true;
 $state['restore_progress_size'] = $streamSize;

 // Temp veri akışı artık tamamıyla hazırlanmış ve kontrol edilmiştır. acil yedek
 // başlatmadan önce, snapshot için gereken disk alanının hâlâ bulunduğunu tekrar kontrol et.
 if (!$recoveryMode) {
 check_sufficient_disk_space(
 $pdo,
 $config['db_name'],
 $backup_dir,
 (int)($state['restore_stream_size'] ?? 0)
 );
 }

 if ($recoveryMode) {
 $state['phase'] = 'clear_database';
 $state['status'] = 'clearing';
 $state['percent'] = 0;
 $state['current_table'] = 'Recovery için veritabanı hazırlanıyor';
 $state['message'] = 'Emergency restore kaynağı doğrulandı. Recovery için mevcut veritabanı temizlenecek.';
 } else {
 // acil yedek'ın tablo listesini ve disk kontrolünü, güncel veri tabanı işlem
 // kilidi alındıktan sonra oluşturacağız. Böylece preflight ile snapshot arasında
 // başka bir DB işleminin şema değiştirip emergency listesini bayatlatması önlenir.
 $state['emergency_job_id'] = '';
 $state['emergency_file'] = '';
 $state['emergency_backup_completed'] = false;
 $state['phase'] = 'emergency_backup';
 $state['status'] = 'waiting';
 $state['percent'] = 0;
 $state['current_table'] = "Mevcut veritabanının emergency snapshot'ı hazırlanıyor";
 $state['message'] = sprintf(
 'Restore kaynağı doğrulandı ve %d SQL sorgusu güvenlik/uyumluluk kontrolünden geçti. Emergency snapshot DB kilidi altında başlatılacak.',
 $queryCount
 );
 }

 Logger::info(sprintf(
 'WEB RESTORE PREFLIGHT BAŞARILI | job_id=%s | file=%s | queries_validated=%d | stream_bytes=%d',
 $job_id,
 $file,
 $queryCount,
 $streamSize
 ));
 } else {
 $state['preflight_offset'] = $offset;
 $state['preflight_file_size'] = $streamSize;
 $state['preflight_queries_validated'] = $queryCount;
 $state['preflight_query_buffer'] = $queryBuffer;
 $state['preflight_in_string'] = $inString;
 $state['preflight_string_char'] = $stringChar;
 $state['preflight_in_comment_multi'] = $inCommentMulti;
 $state['preflight_in_comment_single'] = $inCommentSingle;
 $state['preflight_escaped'] = $escaped;
 $state['preflight_current_delimiter'] = $currentDelimiter;
 $state['preflight_delimiter_line_buffer'] = $delimiterLineBuffer;
 $state['preflight_pending_boundary'] = $pendingBoundary;
 $state['preflight_verified'] = false;
 $state['restore_progress_size'] = $streamSize;
 $state['status'] = 'running';
 $state['phase'] = 'preflight_stream';
 $state['percent'] = (int)floor(($offset / $streamSize) * 99);
 $state['current_table'] = 'Restore SQL doğrulanıyor';
 $state['message'] = sprintf(
 'Restore SQL güvenlik/uyumluluk kontrolü: %s / %s | %d sorgu doğrulandı.',
 format_bytes($offset),
 format_bytes($streamSize),
 $queryCount
 );
 }

 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 // GERİ YÜKLEME ÖNCESİ DB FORMATLAMA
 // acil yedek tamamlandıktan sonra mevcut veri tabanı tek geri yükleme adımında
 // temizlenir. Temizlik tamamlanmadan SQL geri yükleme başlatılmaz.
 if ($phase === 'clear_database') {
 if (empty($state['source_verified']) || empty($state['backup_sha256'])) {
 throw new Exception('Restore kaynağı doğrulanmadan veritabanı temizlenemez.');
 }

 if (empty($state['preflight_verified'])
 || empty($state['restore_stream_ready'])
 || $state['restore_stream_path'] === ''
 || !web_restore_temp_path_is_valid((string)$state['restore_stream_path'], $job_id)) {
 throw new Exception('Restore SQL stream preflight tamamlanmadan veritabanı temizlenemez.');
 }

 $state['status'] = 'clearing';
 $state['phase'] = 'clear_database';
 $state['message'] = 'Restore SQL doğrulandı. Veritabanı tamamen temizleniyor...';
 $state['current_table'] = 'Veritabanına format atılıyor';
 $state['percent'] = 0;
 write_cli_job_state($backup_dir, $job_id, $state);

 $state['destructive_operation_in_progress'] = true;
 write_cli_job_state($backup_dir, $job_id, $state);
 heartbeat_web_worker_locks();
 $clearReport = clear_database_for_restore($pdo, $config['db_name']);
 heartbeat_web_worker_locks();
 $failedCount = count($clearReport['failed'] ?? []);
 if ($failedCount > 0) {
 $firstFailure = $clearReport['failed'][0] ?? [];
 $formatError =
 'Veritabanı temizlenemedi. Nesne: ' . (string)($firstFailure['object'] ?? '-') .
 ' | Tür: ' . (string)($firstFailure['type'] ?? '-') .
 ' | Hata: ' . (string)($firstFailure['reason'] ?? 'Bilinmeyen hata');
 $state['status'] = 'failed';
 $state['phase'] = 'clear_database';
 $state['error'] = $formatError;
 $state['message'] = $formatError;
 write_cli_job_state($backup_dir, $job_id, $state);
 throw new Exception($formatError);
 }

 try {
 $emptyReport = verify_database_is_empty_for_restore($pdo, $config['db_name']);
 } catch (Throwable $e) {
 $state['status'] = 'failed';
 $state['phase'] = 'clear_database';
 $state['error'] = 'Format sonrası boşluk kontrolü başarısız: ' . $e->getMessage();
 $state['message'] = $state['error'];
 write_cli_job_state($backup_dir, $job_id, $state);
 throw $e;
 }
 $state['destructive_operation_in_progress'] = false;

 $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
 $pdo->exec('SET UNIQUE_CHECKS=0');

 $state['phase'] = 'restore';
 $state['status'] = 'running';
 $state['processed_bytes'] = 0;
 $state['file_size'] = (int)filesize($safePath);
 $state['source_file_size'] = $state['file_size'];
 $state['restore_progress_size'] = (int)($state['restore_stream_size'] ?? 0);
 $state['formatted_processed'] = '0 B';
 $state['formatted_total'] = format_bytes((int)($state['restore_stream_size'] ?? 0));
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
 $state['cleanup_report'] = $clearReport['counts'] ?? [];
 $state['message'] = 'Veritabanı formatlandı ve tamamen boş olduğu doğrulandı. Restore başlıyor.';
 $state['current_table'] = 'Restore başlatılıyor';
 write_cli_job_state($backup_dir, $job_id, $state);
 $cleanupCounts = $clearReport['counts'] ?? [];
 Logger::warning(sprintf(
 'WEB RESTORE DB FORMATLANDI | job_id=%s | file=%s | silinen_nesne=%d | tables=%d | views=%d | triggers=%d | procedures=%d | functions=%d | routines=%d | events=%d | kalan=0',
 $job_id,
 $file,
 (int)($cleanupCounts['total'] ?? count($clearReport['dropped'] ?? [])),
 (int)($cleanupCounts['tables'] ?? 0),
 (int)($cleanupCounts['views'] ?? 0),
 (int)($cleanupCounts['triggers'] ?? 0),
 (int)($cleanupCounts['procedures'] ?? 0),
 (int)($cleanupCounts['functions'] ?? 0),
 (int)($cleanupCounts['routines'] ?? 0),
 (int)($cleanupCounts['events'] ?? 0)
 ));
 return $state;
 }

 if ($phase === 'analyze') {
 $analyzeTables = array_values(array_map('strval', $state['analyze_tables'] ?? []));
 $analyzeIndex = (int)($state['analyze_index'] ?? 0);
 $analyzeTotal = count($analyzeTables);
 $analyzeStartedAt = (float)($state['analyze_started_at'] ?? microtime(true));
 $stepStartedAt = microtime(true);
 $maxAnalyzeTablesPerStep = 1;

 // Kullanıcıya hangi tablonun gerçekten ANALYZE edildiğini göster.
 $currentAnalyzeTable = $analyzeIndex < $analyzeTotal
 ? (string)$analyzeTables[$analyzeIndex]
 : 'Tamamlandı';

 $state['analyze_started_at'] = $analyzeStartedAt;
 $state['analyze_current_table'] = $currentAnalyzeTable;
 $state['analyze_running_table'] = $currentAnalyzeTable;
 $state['analyze_in_progress'] = true;
 $state['analyze_last_step_seconds'] = 0.0;
 $state['status'] = 'running';
 $state['phase'] = 'analyze';

 write_cli_job_state($backup_dir, $job_id, $state);

 // Aynı oturumdan gelen ilerleme istekleri durum dosyasını okuyabilsin.
 release_web_session_lock();

 $analysis = analyze_tables_after_restore(
 $config['db_name'],
 $config,
 $analyzeTables,
 $analyzeIndex,
 $maxAnalyzeTablesPerStep,
 $pdo
 );

 $analyzeIndex = (int)($analysis['next_index'] ?? $analyzeIndex);
 $state['analyze_index'] = $analyzeIndex;
 $state['analyze_total'] = $analyzeTotal;
 $state['analyze_successful'] = (int)($state['analyze_successful'] ?? 0) + (int)($analysis['successful'] ?? 0);
 $state['analyze_failed'] = (int)($state['analyze_failed'] ?? 0) + (int)($analysis['failed'] ?? 0);
 $state['analyze_warnings'] = array_values(array_merge(
 (array)($state['analyze_warnings'] ?? []),
 (array)($analysis['warnings'] ?? [])
 ));

 $state['analyze_last_step_seconds'] = round(microtime(true) - $stepStartedAt, 2);
 $state['analyze_elapsed_seconds'] = round(microtime(true) - $analyzeStartedAt, 2);
 $state['estimated_remaining_seconds'] = $analyzeIndex > 0 && $analyzeIndex < $analyzeTotal
 ? max(1, (int)ceil(($state['analyze_elapsed_seconds'] / $analyzeIndex) * ($analyzeTotal - $analyzeIndex)))
 : ($analyzeIndex >= $analyzeTotal ? 0 : null);
 $state['analyze_running_table'] = '';
 $state['analyze_in_progress'] = false;
 $state['analyze_current_table'] = $analyzeIndex < $analyzeTotal
 ? (string)$analyzeTables[$analyzeIndex]
 : 'Tamamlandı';

 $state['status'] = 'running';
 $state['phase'] = 'analyze';

 if ($analyzeTotal > 0) {
 $state['percent'] = min(99, (int)floor(($analyzeIndex / $analyzeTotal) * 100));
 } else {
 $state['percent'] = 99;
 }

 $successful = (int)($state['analyze_successful'] ?? 0);
 $failed = (int)($state['analyze_failed'] ?? 0);

 if ($analyzeIndex < $analyzeTotal) {
 $state['message'] = sprintf(
 'ANALYZE işleniyor: %d/%d | Başarılı: %d | Hatalı: %d | Şimdi: %s | Son adım: %.1f sn | Toplam: %s',
 $analyzeIndex,
 $analyzeTotal,
 $successful,
 $failed,
 $state['analyze_current_table'],
 (float)$state['analyze_last_step_seconds'],
 format_duration_seconds((float)$state['analyze_elapsed_seconds'])
 );
 }

 heartbeat_web_worker_locks();

 if ($analyzeIndex >= $analyzeTotal) {
 $state['status'] = 'completed';
 $state['phase'] = 'completed';
 $state['percent'] = 100;
 $state['message'] = $failed > 0
 ? sprintf(
 'Restore tamamlandı; ANALYZE %d/%d başarılı, %d başarısız. Toplam süre: %s.',
 $successful,
 $analyzeTotal,
 $failed,
 format_duration_seconds((float)$state['analyze_elapsed_seconds'])
 )
 : sprintf(
 'Restore ve ANALYZE tamamlandı; %d/%d tablo analiz edildi. Toplam süre: %s.',
 $successful,
 $analyzeTotal,
 format_duration_seconds((float)$state['analyze_elapsed_seconds'])
 );
 $state['current_table'] = 'Tamamlandı';
 $state['analyze_current_table'] = 'Tamamlandı';

 Logger::info(sprintf(
 'WEB RESTORE ANALYZE TAMAMLANDI | job_id=%s | tables=%d | successful=%d | failed=%d | warnings=%d | duration=%ss',
 $job_id,
 $analyzeTotal,
 $successful,
 $failed,
 count($state['analyze_warnings']),
 (float)$state['analyze_elapsed_seconds']
 ));
 }

 write_cli_job_state($backup_dir, $job_id, $state);
 if (($state['phase'] ?? '') === 'completed') {
 end_restore_maintenance($backup_dir, $job_id);
 }
 return $state;
 }

 if ($phase !== 'restore') return $state;

 if (empty($state['cleanup_verified']) || !isset($state['cleanup_counts'])) {
 throw new Exception('Veritabanı temizliği doğrulanmadan restore devam ettirilemez.');
 }

 $fileSize = (int)($state['file_size'] ?? filesize($safePath));
 $processedBytes = (int)($state['processed_bytes'] ?? 0);
 $startedAt = (float)($state['job_started_at'] ?? microtime(true));

 $streamPath = (string)($state['restore_stream_path'] ?? '');
 if ($streamPath === '' || !is_file($streamPath) || !is_readable($streamPath)) {
 throw new Exception('Web Worker restore geçici SQL stream dosyası bulunamadı.');
 }
 $streamSize = (int)@filesize($streamPath);
 if ($streamSize < 0 || ((int)($state['restore_stream_size'] ?? $streamSize) !== $streamSize)) {
 throw new Exception('Web Worker restore geçici SQL stream boyutu doğrulanamadı.');
 }
 $restoreProgressSize = (int)($state['restore_progress_size'] ?? $streamSize);
 if ($restoreProgressSize !== $streamSize) {
 $restoreProgressSize = $streamSize;
 $state['restore_progress_size'] = $streamSize;
 }

 $fp = @fopen($streamPath, 'rb');
 if (!$fp) throw new Exception('Web Worker restore geçici SQL stream dosyası açılamadı.');
 try {
 if ($processedBytes > 0 && fseek($fp, $processedBytes, SEEK_SET) !== 0) {
 throw new Exception('Web Worker restore SQL stream konumuna gidilemedi.');
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
 $pendingBoundary = (string)($state['parser_pending_boundary'] ?? '');
 $tablesCount = (int)($state['tables_count'] ?? 0);
 $rowsCount = (int)($state['rows_count'] ?? 0);
 $currentRestoreTable = (string)($state['current_table'] ?? '');

 $stepStartedAt = microtime(true);
 $webBudget = get_dynamic_web_step_budget($backup_dir);
 $maxChunksPerStep = (int)$webBudget['max_chunks'];
 $maxStepSeconds = min(5.0, max(1.5, (float)$webBudget['max_step_seconds'] + 0.5));
 $chunksRead = 0;
 $eof = false;

 while ($chunksRead < $maxChunksPerStep && (microtime(true) - $stepStartedAt) < $maxStepSeconds) {
 $rawChunk = fread($fp, get_dynamic_restore_chunk_bytes($backup_dir));
 if ($rawChunk === false) {
 throw new Exception('Web Worker restore verisi okunamadı.');
 }
 if ($rawChunk === '') {
 $eof = feof($fp);
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
 $delimiterLineBuffer,
 $pendingBoundary
 );
 if ($queries) {
 // İş durumunu veri tabanı değişikliğinden önce kalıcılaştır: işlem bu toplu işin ortasında biterse
 // sonraki web isteği aynı SQL'i tekrar yürütmek yerine emergency kurtarma yapar.
 $state['query_in_progress'] = true;
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
 $state['parser_pending_boundary'] = $pendingBoundary;
 $state['tables_count'] = $tablesCount;
 $state['rows_count'] = $rowsCount;
 $state['current_table'] = $currentRestoreTable;
 write_cli_job_state($backup_dir, $job_id, $state);
 heartbeat_web_worker_locks();
 restore_execute_sql($pdo, $queries, $tablesCount, $rowsCount, $backup_dir, $config, $currentRestoreTable);
 heartbeat_web_worker_locks();
 $state['query_in_progress'] = false;
 }

 $eof = feof($fp);
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
 $state['parser_pending_boundary'] = $pendingBoundary;
 $state['tables_count'] = $tablesCount;
 $state['rows_count'] = $rowsCount;
 $state['query_in_progress'] = false;
 $state['destructive_operation_in_progress'] = false;
 $state['current_table'] = $currentRestoreTable !== '' ? $currentRestoreTable : 'Restore çalışıyor';
 $restoreElapsed = max(0.1, microtime(true) - $startedAt);
 $restoreBytesPerSecond = $processedBytes / $restoreElapsed;
 $state['speed_mb_per_second'] = round($restoreBytesPerSecond / 1048576, 2);
 $state['formatted_speed'] = format_transfer_speed($restoreBytesPerSecond);
 if ($processedBytes > 0 && $restoreProgressSize > $processedBytes) {
 $state['estimated_remaining_seconds'] = max(1, (int)ceil(($restoreElapsed / $processedBytes) * ($restoreProgressSize - $processedBytes)));
 } elseif ($restoreProgressSize > 0 && $processedBytes >= $restoreProgressSize) {
 $state['estimated_remaining_seconds'] = 0;
 } else {
 $state['estimated_remaining_seconds'] = null;
 }
 $state['formatted_processed'] = format_bytes($processedBytes);
 $state['formatted_total'] = format_bytes($restoreProgressSize);
 $state['percent'] = $restoreProgressSize > 0 ? min(99, (int)floor(($processedBytes / $restoreProgressSize) * 100)) : 0;

 if ($eof) {
 $finalQuery = finalize_restore_parser(
 $queryBuffer,
 $inString,
 $stringChar,
 $inCommentMulti,
 $inCommentSingle,
 $escaped,
 $currentDelimiter,
 $delimiterLineBuffer,
 $pendingBoundary
 );
 if ($finalQuery !== null) {
 $state['query_in_progress'] = true;
 $state['query_buffer'] = '';
 $state['tables_count'] = $tablesCount;
 $state['rows_count'] = $rowsCount;
 write_cli_job_state($backup_dir, $job_id, $state);
 heartbeat_web_worker_locks();
 restore_execute_sql($pdo, [$finalQuery], $tablesCount, $rowsCount, $backup_dir, $config, $currentRestoreTable);
 heartbeat_web_worker_locks();
 $state['query_in_progress'] = false;
 $state['tables_count'] = $tablesCount;
 $state['rows_count'] = $rowsCount;
 }

 $pdo->exec('SET UNIQUE_CHECKS=1');
 $pdo->exec('SET FOREIGN_KEY_CHECKS=1');

 heartbeat_web_worker_locks();
 $integrity = $config['verify_after_restore']
 ? verify_database_integrity_after_restore($pdo, $config['db_name'], true, false)
 : ['status' => 'SKIPPED', 'tables_checked' => 0, 'fk_issues' => 0, 'errors' => []];

 heartbeat_web_worker_locks();

 if (($integrity['status'] ?? '') === 'FAILED' || !empty($integrity['errors'])) {
 throw new Exception('Restore sonrası bütünlük kontrolü başarısız.');
 }

 write_web_restore_commit_marker($backup_dir, $job_id, [
 'file' => $file,
 'original_restore_file' => (string)($state['original_restore_file'] ?? ''),
 'emergency_file' => (string)($state['emergency_file'] ?? ''),
 'backup_sha256' => (string)($state['backup_sha256'] ?? ''),
 'processed_bytes' => $restoreProgressSize,
 'restore_progress_size' => $restoreProgressSize,
 'integrity' => $integrity,
 'recovery_mode' => $recoveryMode,
 ]);

 $state['restore_verified'] = true;
 $state['query_in_progress'] = false;
 $state['destructive_operation_in_progress'] = false;
 $completedEmergencyFile = (string)($state['emergency_file'] ?? '');
 $emergencyJobId = (string)($state['emergency_job_id'] ?? '');
 // Başarılı geri yükleme sonrasında kullanılan geçici emergency kaynağı temizlenir.
 if ($completedEmergencyFile !== '') {
 cleanup_emergency_backup_artifacts($backup_dir, $completedEmergencyFile);
 }
 if (preg_match('/^[a-f0-9]{32}$/', $emergencyJobId)) {
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json');
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json.tmp');
 }
 $state['emergency_file'] = '';
 $state['emergency_backup_completed'] = false;
 cleanup_web_restore_stream_cache($state);
 $state['restore_stream_path'] = '';
 $state['restore_stream_size'] = 0;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = 0;

 $duration = round(microtime(true) - $startedAt, 2);
 $state['processed_bytes'] = $restoreProgressSize;
 $state['restore_progress_size'] = $restoreProgressSize;
 $state['formatted_processed'] = format_bytes($restoreProgressSize);
 $state['formatted_total'] = format_bytes($restoreProgressSize);
 $state['file_size'] = $fileSize;
 $state['source_file_size'] = $fileSize;
 $state['percent'] = 100;
 $state['duration_seconds'] = $duration;
 $state['backup_sha256'] = (string)($state['backup_sha256'] ?? '');
 $state['integrity'] = $integrity;

 if (!$recoveryMode && (bool)$config['analyze_after_restore']) {
 // WEB modu seçildiği için ANALYZE kesinlikle WEB işçi sürecinde kalır.
 // Bir sonraki ilerleme isteğinde run_web_worker_step() veri tabanı kilidini
 // alır ve yalnızca bir tabloyu ANALYZE edip durumu günceller.
 $state['engine'] = 'web';
 $state['status'] = 'waiting';
 $state['phase'] = 'analyze';
 $state['analyze_engine'] = 'web';
 $state['percent'] = 99;
 $state['analyze_index'] = 0;
 $state['analyze_tables'] = get_web_worker_tables($pdo, $config['db_name']);
 $state['analyze_total'] = count($state['analyze_tables']);
 $state['analyze_successful'] = 0;
 $state['analyze_failed'] = 0;
 $state['analyze_warnings'] = [];
 $state['analyze_started_at'] = microtime(true);
 $state['analyze_current_table'] = $state['analyze_tables'][0] ?? 'Yok';
 $state['analyze_elapsed_seconds'] = 0.0;
 $state['analyze_last_step_seconds'] = 0.0;
 $state['analyze_in_progress'] = false;
 $state['analyze_running_table'] = '';
 $state['message'] = 'Restore tamamlandı. Web Worker ANALYZE için hazır.';
 $state['current_table'] = $state['analyze_current_table'];
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 $state['status'] = 'completed';
 $state['phase'] = 'completed';
 $state['percent'] = 100;
 $state['message'] = $recoveryMode ? 'Recovery başarıyla tamamlandı; eski veritabanı geri yüklendi.' : 'Restore başarıyla tamamlandı.';
 if ($recoveryMode) {
 $state['recovered'] = true;
 $state['original_restore_file'] = (string)($state['original_restore_file'] ?? '');
 $state['file'] = $state['original_restore_file'];
 $state['recovery_source_file'] = $completedEmergencyFile;
 }
 $state['current_table'] = 'Tamamlandı';
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
 $state['percent'] = $restoreProgressSize > 0 ? min(99, (int)floor(($processedBytes / $restoreProgressSize) * 100)) : 0;
 $state['message'] = $chunksRead > 0
 ? sprintf('Restore devam ediyor... (%d chunk)', $chunksRead)
 : 'Restore devam ediyor...';
 }

 write_cli_job_state($backup_dir, $job_id, $state);
 if (($state['phase'] ?? '') === 'completed') {
 end_restore_maintenance($backup_dir, $job_id);
 }
 if (($state['phase'] ?? '') === 'completed' || ($state['phase'] ?? '') === 'analyze_pending') {
 delete_web_restore_commit_marker($backup_dir, $job_id);
 }
 } finally {
 @fclose($fp);
 }

 return $state;
}

function initialize_web_restore_job(PDO $pdo, string $backup_dir, array $config, string $job_id, string $file)
: array {
 $admissionLock = acquire_job_admission_lock($backup_dir);
 if (!$admissionLock) {
 throw new Exception('Başka bir backup/restore işlemi başlatılıyor. Lütfen tekrar deneyin.');
 }

 try {
 cleanup_stale_cli_job_states($backup_dir);
 assert_no_active_database_job($backup_dir, $job_id);
 if (!validate_backup_filename($file)) throw new Exception('Geçersiz restore dosyası.');
 $safePath = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
 if (!is_file($safePath)) throw new Exception('Restore dosyası bulunamadı.');
 check_sufficient_disk_space($pdo, $config['db_name'], $backup_dir);
 $sourceSizeForTemp = (int)@filesize($safePath);
 $freeForRestore = @disk_free_space($backup_dir);
 if ($freeForRestore !== false && $sourceSizeForTemp > 0) {
 $requiredRestoreHeadroom = min(16 * 1024 * 1024 * 1024, max(128 * 1024 * 1024, $sourceSizeForTemp * 4));
 if ($freeForRestore < $requiredRestoreHeadroom) {
 throw new Exception('WEB restore için geçici SQL stream ve recovery snapshot alanı yetersiz.');
 }
 }

 begin_restore_maintenance($backup_dir, $job_id, 'web');
 $state = [
 'job_id' => $job_id,
 'engine' => 'web',
 'type' => 'restore',
 'status' => 'starting',
 'phase' => 'verify_source',
 'file' => $file,
 'file_size' => (int)filesize($safePath),
 'source_file_size' => (int)filesize($safePath),
 'processed_bytes' => 0,
 'restore_progress_size' => 0,
 'job_started_at' => microtime(true),
 'message' => 'Restore kaynağı doğrulanacak, ardından veritabanı tamamen temizlenecek.',
 'fallback_reason' => (string)($config['_web_fallback_reason'] ?? 'CLI kullanılamıyor.'),
 'source_verified' => false,
 'source_gzip_verified' => false,
 'preflight_verified' => false,
 'preflight_source_verified' => false,
 'preflight_offset' => 0,
 'preflight_file_size' => 0,
 'preflight_queries_validated' => 0,
 'preflight_query_buffer' => '',
 'preflight_in_string' => false,
 'preflight_string_char' => '',
 'preflight_in_comment_multi' => false,
 'preflight_in_comment_single' => false,
 'preflight_escaped' => false,
 'preflight_current_delimiter' => ';',
 'preflight_delimiter_line_buffer' => '',
 'preflight_pending_boundary' => '',
 'cleanup_verified' => false,
 'restore_stream_path' => '',
 'restore_stream_size' => 0,
 'restore_stream_ready' => false,
 'restore_stream_created_at' => 0,
 'prepare_stream_completed' => false,
 'prepare_stream_status' => '',
 'prepare_stream_pid' => 0,
 'prepare_stream_percent' => 0,
 'prepare_stream_bytes_written' => 0,
 'prepare_stream_source_offset' => 0,
 'prepare_stream_source_size' => 0,
 'prepare_stream_source_mtime' => 0,
 'prepare_stream_last_step_seconds' => 0.0,
 'prepare_stream_last_step_bytes' => 0,
 'prepare_stream_last_seek_seconds' => 0.0,
 'prepare_stream_generation' => 0,
 'prepare_stream_worker_token' => '',
 'clear_initialized' => false,
 'clear_stage' => 'views_tables',
 'clear_processed' => 0,
 'clear_total' => 0,
 'clear_counts' => [
 'tables' => 0, 'views' => 0, 'triggers' => 0,
 'procedures' => 0, 'functions' => 0, 'routines' => 0,
 'events' => 0, 'sequences' => 0, 'total' => 0
 ],
 'clear_initial_counts' => [
 'tables' => 0, 'views' => 0, 'triggers' => 0,
 'procedures' => 0, 'functions' => 0, 'routines' => 0,
 'events' => 0, 'sequences' => 0, 'total' => 0
 ],
 'destructive_operation_in_progress' => false,
 'query_in_progress' => false
 ];
 write_cli_job_state($backup_dir, $job_id, $state);
 Logger::warning(sprintf(
 'WEB WORKER RESTORE BAŞLATILDI | job_id=%s | file=%s | reason=%s',
 $job_id,
 $file,
 $state['fallback_reason']
 ));
 return $state;
 } catch (Throwable $e) {
 end_restore_maintenance($backup_dir, $job_id);
 throw $e;
 } finally {
 release_job_admission_lock($admissionLock);
 }
}
function prepare_web_restore_recovery_state(string $backup_dir, string $job_id, Throwable $error)
: ?array {
 $state = read_cli_job_state($backup_dir, $job_id);
 if (!$state || ($state['engine'] ?? '') !== 'web' || ($state['type'] ?? '') !== 'restore') {
 return null;
 }

 // kurtarma sırasında tekrar kurtarma başlatma; bu ikinci hata doğrudan failed olarak kalır.
 if (!empty($state['recovery_mode'])) {
 return null;
 }

 $emergencyFile = (string)($state['emergency_file'] ?? '');
 if ($emergencyFile === '' || !is_emergency_backup_filename($emergencyFile) || !validate_backup_filename($emergencyFile)) {
 return null;
 }

 try {
 $safeEmergencyPath = validate_path_safe($backup_dir . '/' . $emergencyFile, $backup_dir);
 } catch (Throwable $pathError) {
 Logger::error('WEB RESTORE RECOVERY HAZIRLANAMADI | job_id=' . $job_id . ' | emergency=' . $emergencyFile . ' | path_error=' . $pathError->getMessage());
 return null;
 }

 if (!is_file($safeEmergencyPath)) {
 Logger::error('WEB RESTORE RECOVERY HAZIRLANAMADI | job_id=' . $job_id . ' | emergency dosya bulunamadı=' . $emergencyFile);
 return null;
 }

 $originalFile = (string)($state['original_restore_file'] ?? $state['file'] ?? '');
 if ($originalFile === '' || !validate_backup_filename($originalFile)) {
 Logger::error('WEB RESTORE RECOVERY HAZIRLANAMADI | job_id=' . $job_id . ' | original file geçersiz.');
 return null;
 }

 $state['recovery_mode'] = true;
 $state['original_restore_file'] = $originalFile;
 $state['recovery_source_file'] = $emergencyFile;
 $state['file'] = $emergencyFile;
 $state['emergency_file'] = $emergencyFile;
 $state['emergency_backup_completed'] = true;
 $state['source_verified'] = false;
 $state['source_gzip_verified'] = false;
 $state['preflight_verified'] = false;
 $state['preflight_queries_validated'] = 0;
 $state['cleanup_verified'] = false;
 $state['restore_verified'] = false;
 $state['verify_offset'] = 0;
 $state['verify_file_size'] = (int)@filesize($safeEmergencyPath);
 $state['verify_hash_context'] = '';
 $state['preflight_offset'] = 0;
 $state['preflight_file_size'] = 0;
 $state['preflight_queries_validated'] = 0;
 $state['preflight_query_buffer'] = '';
 $state['preflight_in_string'] = false;
 $state['preflight_string_char'] = '';
 $state['preflight_in_comment_multi'] = false;
 $state['preflight_in_comment_single'] = false;
 $state['preflight_escaped'] = false;
 $state['preflight_current_delimiter'] = ';';
 $state['preflight_delimiter_line_buffer'] = '';
 $state['processed_bytes'] = 0;
 $state['restore_progress_size'] = 0;
 $state['destructive_operation_in_progress'] = false;
 $state['query_in_progress'] = false;
 $state['source_file_size'] = (int)($state['verify_file_size'] ?? 0);
 $state['formatted_processed'] = '0 B';
 $state['formatted_total'] = '0 B';
 $state['query_buffer'] = '';
 $state['in_string'] = false;
 $state['string_char'] = '';
 $state['in_comment_multi'] = false;
 $state['in_comment_single'] = false;
 $state['escaped'] = false;
 $state['current_delimiter'] = ';';
 $state['delimiter_line_buffer'] = '';
 $state['parser_pending_boundary'] = '';
 $state['tables_count'] = 0;
 $state['rows_count'] = 0;
 $state['current_table'] = 'Recovery kaynağı doğrulanıyor';
 cleanup_web_restore_stream_cache($state);
 $state['restore_stream_path'] = '';
 $state['restore_stream_size'] = 0;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = 0;
 $state['prepare_stream_generation'] = (int)($state['prepare_stream_generation'] ?? 0) + 1;
 $state['prepare_stream_worker_token'] = '';
 $state['prepare_stream_completed'] = false;
 $state['prepare_stream_status'] = '';
 $state['prepare_stream_pid'] = 0;
 $state['prepare_stream_percent'] = 0;
 $state['prepare_stream_bytes_written'] = 0;
 $state['prepare_stream_source_offset'] = 0;
 $state['prepare_stream_source_size'] = 0;
 $state['prepare_stream_source_mtime'] = 0;
 $state['prepare_stream_last_step_seconds'] = 0.0;
 $state['prepare_stream_last_step_bytes'] = 0;
 $state['prepare_stream_last_seek_seconds'] = 0.0;
 $state['clear_initialized'] = false;
 $state['clear_stage'] = 'views_tables';
 $state['clear_processed'] = 0;
 $state['clear_total'] = 0;
 $state['clear_counts'] = [
 'tables' => 0, 'views' => 0, 'triggers' => 0,
 'procedures' => 0, 'functions' => 0, 'routines' => 0,
 'events' => 0, 'sequences' => 0, 'total' => 0
 ];
 $state['clear_initial_counts'] = [
 'tables' => 0, 'views' => 0, 'triggers' => 0,
 'procedures' => 0, 'functions' => 0, 'routines' => 0,
 'events' => 0, 'sequences' => 0, 'total' => 0
 ];
 $state['phase'] = 'verify_source';
 $state['status'] = 'waiting';
 $state['percent'] = 0;
 $state['recovery_error'] = $error->getMessage();
 $state['message'] = 'Restore başarısız oldu. Eski veritabanı Web Worker emergency snapshot üzerinden geri yüklenmeye hazırlanıyor.';

 write_cli_job_state($backup_dir, $job_id, $state);
 Logger::warning(sprintf(
 'WEB RESTORE RECOVERY HAZIRLANDI | job_id=%s | original_file=%s | emergency_file=%s | error=%s',
 $job_id,
 $originalFile,
 $emergencyFile,
 $error->getMessage()
 ));

 return $state;
}

/**
 * WEB işinin sıradaki adımını çalıştırır. Aynı anda iki veri tabanı işi başlamasın diye ortak bir kilit kullanır.
 */
function run_web_worker_step(PDO $pdo, string $backup_dir, array $config, string $job_id)
: array {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 throw new Exception('Geçersiz Web Worker job ID.');
 }

 $worker_lock = acquire_system_lock(
 $backup_dir,
 'web_worker_' . $job_id,
 0
 );

 if (!$worker_lock) {
 $waitingState = read_cli_job_state($backup_dir, $job_id);
 if (!$waitingState || ($waitingState['engine'] ?? '') !== 'web') {
 return $waitingState;
 }
 $waitingState['status'] = 'waiting';
 $waitingState['message'] = 'Aynı Web Worker işi başka bir istekte yürütülüyor.';
 return $waitingState;
 }

 try {
 $state = read_cli_job_state($backup_dir, $job_id);
 if (!$state || ($state['engine'] ?? '') !== 'web') {
 return $state;
 }

 if (($state['type'] ?? '') === 'restore' && web_restore_state_needs_stale_recovery($state)) {
 $recoveryState = prepare_web_restore_recovery_state(
 $backup_dir,
 $job_id,
 new Exception('Web Worker restore durumu stale kaldı; olası süreç kesintisi nedeniyle emergency snapshot recovery başlatıldı.')
 );
 if ($recoveryState !== null) return $recoveryState;
 }

 $state['step_started_at'] = microtime(true);
 $phase = (string)($state['phase'] ?? '');

 // WEB modu seçildiyse ANALYZE de tamamen Web işçi süreci içinde çalışır.
 // Bu noktada sadece fazı hazırlarız; aşağıda alınacak veri tabanı kilidi
 // ile bir sonraki tek tablolu ANALYZE adımı çalıştırılır.
 if (($state['type'] ?? '') === 'restore' && $phase === 'analyze_pending') {
 $state['engine'] = 'web';
 $state['status'] = 'waiting';
 $state['phase'] = 'analyze';
 $state['analyze_engine'] = 'web';
 $state['percent'] = 99;
 $state['message'] = 'Restore tamamlandı. Web Worker ANALYZE başlatılıyor.';
 $state['current_table'] = $state['analyze_current_table'] ?? 'ANALYZE hazırlanıyor';
 write_cli_job_state($backup_dir, $job_id, $state);
 $phase = 'analyze';
 }

 if (($state['type'] ?? '') === 'restore'
 && in_array($phase, ['verify_source', 'verifying', 'prepare_stream', 'preflight_stream'], true)) {
 $GLOBALS['VEDO_WEB_WORKER_JOB_LOCK_HANDLE'] = $worker_lock;
 try {
 update_system_lock_heartbeat($worker_lock);
 try {
 return web_restore_step($pdo, $job_id, $backup_dir, $config);
 } catch (Throwable $restoreError) {
 $recoveryState = prepare_web_restore_recovery_state($backup_dir, $job_id, $restoreError);
 if ($recoveryState !== null) {
 return $recoveryState;
 }
 throw $restoreError;
 }
 } finally {
 unset($GLOBALS['VEDO_WEB_WORKER_JOB_LOCK_HANDLE']);
 }
 }

 $admission_lock = acquire_job_admission_lock($backup_dir);
 if (!$admission_lock) {
 $state['status'] = 'waiting';
 $state['message'] = 'Yeni bir veritabanı işlemi başlatılırken Web Worker sırası bekliyor.';
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 try {
 assert_restore_maintenance_marker_valid($backup_dir, $job_id);
 assert_no_active_database_job($backup_dir, $job_id);
 $lock_handle = acquire_system_lock(
 $backup_dir,
 VEDO_DATABASE_OPERATION_LOCK,
 max(0, (int)($config['lock_timeout'] ?? 60))
 );

 if (!$lock_handle) {
 $state['status'] = 'waiting';
 $state['message'] = 'Başka bir veritabanı işlemi aktif; Web Worker devam etmek için bekliyor.';
 $state['current_table'] = 'Veritabanı işlemi bekleniyor';
 write_cli_job_state($backup_dir, $job_id, $state);
 return $state;
 }

 try {
 $GLOBALS['VEDO_WEB_WORKER_JOB_LOCK_HANDLE'] = $worker_lock;
 $GLOBALS['VEDO_WEB_WORKER_DB_LOCK_HANDLE'] = $lock_handle;

 update_system_lock_heartbeat($worker_lock);
 update_system_lock_heartbeat($lock_handle);

 // veri tabanı kilidinden sonra en güncel iş durumunu al; bekleyen web isteği eski konumla
 // aynı SQL parçasını ikinci kez yürütmesin.
 $freshState = read_cli_job_state($backup_dir, $job_id);
 if (is_array($freshState) && $freshState !== []) $state = $freshState;
 if (($state['status'] ?? '') === 'completed') return $state;

 if (($state['type'] ?? '') === 'restore' && web_restore_state_needs_stale_recovery($state)) {
 $recoveryState = prepare_web_restore_recovery_state(
 $backup_dir,
 $job_id,
 new Exception('Web Worker restore state stale; emergency snapshot recovery başlatıldı.')
 );
 if ($recoveryState !== null) return $recoveryState;
 }

 if (($state['type'] ?? '') === 'backup') {
 return web_backup_step($pdo, $job_id, $backup_dir, $config);
 }

 if (($state['type'] ?? '') === 'restore') {
 if ((string)($state['phase'] ?? '') === 'emergency_backup') {
 $emergencyJobId = (string)($state['emergency_job_id'] ?? '');
 if ($emergencyJobId === '') {
 // Ana geri yükleme işi preflight aşamasını tamamladı; acil yedek işini burada,
 // ortak DB işlem kilidi zaten tutulurken oluştur.
 $emergencyState = initialize_web_emergency_backup_job($pdo, $backup_dir, $config, $job_id, (int)($state['restore_stream_size'] ?? 0));
 $emergencyJobId = (string)$emergencyState['job_id'];
 $state['emergency_job_id'] = $emergencyJobId;
 $state['emergency_file'] = '';
 $state['emergency_backup_completed'] = false;
 $state['status'] = 'waiting';
 $state['percent'] = 0;
 $state['current_table'] = "Mevcut veritabanının emergency snapshot'ı alınıyor";
 $state['message'] = 'Emergency snapshot DB işlem kilidi altında başlatıldı.';
 write_cli_job_state($backup_dir, $job_id, $state);
 } else {
 if (!preg_match('/^[a-f0-9]{32}$/', $emergencyJobId)) {
 throw new Exception('Web emergency backup job ID bulunamadı.');
 }
 $emergencyState = read_cli_job_state($backup_dir, $emergencyJobId);
 if (!$emergencyState || empty($emergencyState['is_emergency_backup'])) {
 throw new Exception('Web emergency backup işi bulunamadı.');
 }
 }
 $result = web_backup_step($pdo, $emergencyJobId, $backup_dir, $config);
 $latestParent = read_cli_job_state($backup_dir, $job_id) ?: $state;
 if (($result['status'] ?? '') === 'completed') {
 $latestParent['emergency_file'] = (string)($result['file'] ?? '');
 $latestParent['emergency_backup_completed'] = true;
 $latestParent['phase'] = 'clear_database';
 $latestParent['status'] = 'clearing';
 $latestParent['percent'] = 0;
 $latestParent['estimated_remaining_seconds'] = null;
 $latestParent['formatted_speed'] = '';
 $latestParent['message'] = 'Web emergency snapshot tamamlandı. Mevcut veritabanı şimdi temizlenecek.';
 write_cli_job_state($backup_dir, $job_id, $latestParent);
 } else {
 $emergencyPercent = max(0, min(99, (int)($result['percent'] ?? $result['emergency_percent'] ?? 0)));
 $latestParent['status'] = 'waiting';
 // acil yedek ilerlemesini ana iş durumuna aktar. Arayüz ana iş
 // kaydını okuduğu için yalnızca alt işin durumunu güncellemek yeterli değildir.
 $latestParent['percent'] = $emergencyPercent;
 $latestParent['emergency_percent'] = $emergencyPercent;
 $latestParent['current_table'] = (string)($result['current_table'] ?? 'Emergency snapshot hazırlanıyor');
 $latestParent['current_table_index'] = (int)($result['current_table_index'] ?? 0);
 $latestParent['total_tables'] = (int)($result['total_tables'] ?? 0);
 $latestParent['processed_rows'] = (int)($result['processed_rows'] ?? 0);
 $latestParent['elapsed_seconds'] = (float)($result['elapsed_seconds'] ?? 0);
 $latestParent['speed_rows_per_second'] = (int)($result['speed_rows_per_second'] ?? 0);
 $latestParent['bytes_written'] = (int)($result['bytes_written'] ?? 0);
 $latestParent['formatted_bytes'] = (string)($result['formatted_bytes'] ?? '0 B');
 $latestParent['speed_mb_per_second'] = (float)($result['speed_mb_per_second'] ?? 0);
 $latestParent['formatted_speed'] = (string)($result['formatted_speed'] ?? format_transfer_speed(((float)($result['bytes_written'] ?? 0)) / max(0.1, (float)($result['elapsed_seconds'] ?? 0))));
 $latestParent['estimated_remaining_seconds'] = isset($result['estimated_remaining_seconds']) && $result['estimated_remaining_seconds'] !== null
 ? max(1, (int)$result['estimated_remaining_seconds'])
 : null;
 $latestParent['emergency_activity_tick'] = (int)($latestParent['emergency_activity_tick'] ?? 0) + 1;
 $latestParent['message'] = (string)($result['message'] ?? 'Web emergency snapshot devam ediyor.');
 write_cli_job_state($backup_dir, $job_id, $latestParent);
 }
 return $latestParent;
 }
 try {
 return web_restore_step($pdo, $job_id, $backup_dir, $config);
 } catch (Throwable $restoreError) {
 $recoveryState = prepare_web_restore_recovery_state($backup_dir, $job_id, $restoreError);
 if ($recoveryState !== null) {
 return $recoveryState;
 }
 throw $restoreError;
 }
 }

 throw new Exception('Bilinmeyen Web Worker iş tipi.');
 } finally {
 unset($GLOBALS['VEDO_WEB_WORKER_DB_LOCK_HANDLE']);
 unset($GLOBALS['VEDO_WEB_WORKER_JOB_LOCK_HANDLE']);
 if (isset($lock_handle) && is_resource($lock_handle)) release_system_lock($lock_handle);
 }
 } finally {
 release_job_admission_lock($admission_lock);
 }
 } finally {
 release_system_lock($worker_lock);
 }
}
function reconnect_restore_pdo_for_recovery(PDO &$pdo, array $config)
: void {
 // 2006/2013 gibi bağlantı kopmalarında mevcut PDO nesnesi güvenilmez olabilir.
 // Emergency geri yükleme başlamadan önce bağlantıyı tamamen bırakıp temiz bir PDO aç.
 $pdo = null;
 gc_collect_cycles();

 $pdo = get_pdo(
 (string)$config['db_host'],
 (string)$config['db_user'],
 (string)$config['db_pass'],
 (string)$config['db_name'],
 true,
 (bool)($config['use_persistent_pdo'] ?? false)
 );
 $pdo->exec('SET FOREIGN_KEY_CHECKS=0');
 $pdo->exec('SET UNIQUE_CHECKS=0');
}


// =============================================================================
// PHP - CLI GERİ YÜKLEME MOTORU
// Komut satırı çalışanı kullanılabiliyorsa geri yükleme işlemini web isteğinden
// bağımsız yürütür. Büyük işlemler için daha uygun ve daha dayanıklı yöntemdir.
// =============================================================================

function perform_restore_cli_job(
 PDO $pdo,
 string $file,
 string $backup_dir,
 array $config,
 $lock_handle,
 string $job_id,
 bool $create_emergency_backup = true
)
: void {
 $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
 if (!is_file($safe_path) || !validate_backup_filename($file)) {
 throw new Exception('Geçersiz veya bulunamayan restore dosyası.');
 }

 $file_size = (int)filesize($safe_path);
 $processed_bytes = 0;
 $tables_count = 0;
 $rows_count = 0;
 $started_at = microtime(true);
 $emergency_file = '';
 $restore_verified = false;

 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'engine' => 'cli',
 'status' => 'starting',
 'phase' => 'starting',
 'percent' => 0,
 'file' => $file,
 'tables_count' => 0,
 'rows_count' => 0,
 'source_verified' => false,
 'cleanup_verified' => false,
 'cleanup_report' => [],
 'job_started_at' => $started_at,
 'elapsed_seconds' => 0
 ]);

 try {
 $backup_sha256 = verify_restore_source_integrity($safe_path);
 Logger::info(sprintf('CLI RESTORE KAYNAK DOĞRULANDI | file=%s | sha256=%s', $file, $backup_sha256));

 // DESTRUCTIVE İŞLEM ÖNCESİ TAM PREFLIGHT: dosya doğrulama özeti zaten doğrulandığı için
 // ikinci kez ham .gz SHA256 hesaplamadan yalnızca gzip + SQL uyumluluğu taranır.
 $compatibility = validate_backup_restore_compatibility($safe_path, false, (string)$config['db_name']);
 Logger::info(sprintf(
 'CLI RESTORE PREFLIGHT BAŞARILI | file=%s | queries_validated=%d',
 $file,
 (int)($compatibility['queries_validated'] ?? 0)
 ));

 if ($create_emergency_backup) {
 Logger::warning('CLI RESTORE ÖNCESİ EMERGENCY SNAPSHOT BAŞLADI | job_id=' . $job_id . ' | db=' . $config['db_name']);
 $emergencyProgressCallback = static function (array $emergencyState) use ($backup_dir, $job_id): void {
 $parentState = read_cli_job_state($backup_dir, $job_id) ?: [];
 $percent = (int)($emergencyState['percent'] ?? 0);
 $parentState['status'] = 'waiting';
 $parentState['phase'] = 'emergency_backup';
 $parentState['percent'] = $percent;
 $parentState['emergency_percent'] = $percent;
 $parentState['current_table'] = (string)($emergencyState['current_table'] ?? 'Emergency snapshot hazırlanıyor');
 $parentState['current_table_index'] = (int)($emergencyState['current_table_index'] ?? 0);
 $parentState['total_tables'] = (int)($emergencyState['total_tables'] ?? 0);
 $parentState['processed_rows'] = (int)($emergencyState['processed_rows'] ?? 0);
 $parentState['formatted_speed'] = (string)($emergencyState['formatted_speed'] ?? format_transfer_speed(((float)($emergencyState['bytes_written'] ?? 0)) / max(0.1, (float)($emergencyState['elapsed_seconds'] ?? 0))));
 $parentState['estimated_remaining_seconds'] = isset($emergencyState['estimated_remaining_seconds']) && $emergencyState['estimated_remaining_seconds'] !== null
 ? max(1, (int)$emergencyState['estimated_remaining_seconds'])
 : null;
 $parentState['emergency_activity_tick'] = (int)($parentState['emergency_activity_tick'] ?? 0) + 1;
 $parentState['message'] = sprintf(
 'Emergency snapshot: %s',
 (string)($emergencyState['current_table'] ?? 'çalışıyor')
 );
 write_cli_job_state($backup_dir, $job_id, $parentState);
 };
 $emergency_path = perform_backup(
 $pdo,
 $config['db_name'],
 $backup_dir,
 $config,
 $lock_handle,
 $emergencyProgressCallback,
 '.vedo_emergency_cli_' . $job_id,
 false
 );
 $emergency_file = basename($emergency_path);
 verify_backup_checksum($emergency_path);
 Logger::warning(sprintf(
 'CLI RESTORE ÖNCESİ EMERGENCY SNAPSHOT TAMAMLANDI | job_id=%s | file=%s',
 $job_id,
 $emergency_file
 ));
 }

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
 $cleanupCounts = $clearReport['counts'] ?? [];
 Logger::warning(sprintf(
 'CLI RESTORE DB FORMATLANDI | file=%s | silinen_nesne=%d | tables=%d | views=%d | triggers=%d | procedures=%d | functions=%d | routines=%d | events=%d | kalan=0',
 $file,
 (int)($cleanupCounts['total'] ?? count($clearReport['dropped'] ?? [])),
 (int)($cleanupCounts['tables'] ?? 0),
 (int)($cleanupCounts['views'] ?? 0),
 (int)($cleanupCounts['triggers'] ?? 0),
 (int)($cleanupCounts['procedures'] ?? 0),
 (int)($cleanupCounts['functions'] ?? 0),
 (int)($cleanupCounts['routines'] ?? 0),
 (int)($cleanupCounts['events'] ?? 0)
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
 $pending_boundary = '';
 $current_restore_table = '';

 try {
 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'engine' => 'cli',
 'status' => 'running',
 'phase' => 'restore',
 'percent' => 0,
 'file' => $file,
 'job_started_at' => $started_at,
 'tables_count' => 0,
 'rows_count' => 0,
 'cleanup_report' => $cleanupCounts
 ]);

 while (!gzeof($gz)) {
 $raw_chunk = gzread($gz, get_dynamic_restore_chunk_bytes());
 if ($raw_chunk === false) throw new Exception('Gzip restore verisi okunamadı.');
 if ($raw_chunk === '') {
 if (gzeof($gz)) break;
 continue;
 }

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
 $current_delimiter,
 $delimiter_line_buffer,
 $pending_boundary
 );

 if ($queries) {
 restore_execute_sql($pdo, $queries, $tables_count, $rows_count, $backup_dir, $config, $current_restore_table);
 }

 if (($processed_bytes % (16 * 1024 * 1024)) < $read_len) {
 $pct = $file_size > 0 ? min(99, (int)floor(($processed_bytes / $file_size) * 100)) : 0;
 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'engine' => 'cli',
 'status' => 'running',
 'phase' => 'restore',
 'percent' => $pct,
 'file' => $file,
 'job_started_at' => $started_at,
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

 $final_query = finalize_restore_parser($query_buffer, $in_string, $string_char, $in_comment_multi, $in_comment_single, $escaped, $current_delimiter, $delimiter_line_buffer, $pending_boundary);
 if ($final_query !== null) {
 restore_execute_sql($pdo, [$final_query], $tables_count, $rows_count, $backup_dir, $config, $current_restore_table);
 }

 $pdo->exec('SET UNIQUE_CHECKS=1');
 $pdo->exec('SET FOREIGN_KEY_CHECKS=1');

 $integrity = $config['verify_after_restore']
 ? verify_database_integrity_after_restore($pdo, $config['db_name'], true, false)
 : ['status' => 'SKIPPED', 'tables_checked' => 0, 'fk_issues' => 0, 'errors' => []];

 if (($integrity['status'] ?? '') === 'FAILED' || !empty($integrity['errors'])) {
 throw new Exception('Restore sonrası bütünlük kontrolü başarısız.');
 }

 $restore_verified = true;
 if ($emergency_file !== '') {
 cleanup_emergency_backup_artifacts($backup_dir, $emergency_file);
 $emergency_file = '';
 }

 $analyzeReport = [
 'processed' => 0,
 'successful' => 0,
 'failed' => 0,
 'next_index' => 0,
 'total' => 0,
 'warnings' => []
 ];
 if ((bool)$config['analyze_after_restore']) {
 $analyzeTables = get_web_worker_tables($pdo, $config['db_name']);
 $analyzeReport = analyze_tables_after_restore(
 $config['db_name'],
 $config,
 $analyzeTables,
 0,
 0,
 $pdo
 );
 Logger::info(sprintf(
 'RESTORE ANALYZE TAMAMLANDI | tables=%d | successful=%d | failed=%d',
 (int)($analyzeReport['total'] ?? 0),
 (int)($analyzeReport['successful'] ?? 0),
 (int)($analyzeReport['failed'] ?? 0)
 ));
 if (!empty($analyzeReport['warnings'])) {
 Logger::warning(
 'RESTORE ANALYZE UYARILARI | ' .
 implode(' | ', array_map('strval', $analyzeReport['warnings']))
 );
 }
 }

 @gzclose($gz);
 $gz = null;

 $restore_duration = round(microtime(true) - $started_at, 2);
 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'engine' => 'cli',
 'status' => 'completed',
 'phase' => 'restore',
 'percent' => 100,
 'file' => $file,
 'job_started_at' => $started_at,
 'tables_count' => $tables_count,
 'rows_count' => $rows_count,
 'current_table' => 'Tamamlandı',
 'processed_bytes' => $file_size,
 'file_size' => $file_size,
 'duration_seconds' => $restore_duration,
 'backup_sha256' => $backup_sha256,
 'integrity' => $integrity,
 'analyze' => $analyzeReport
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

 if ($create_emergency_backup && !$restore_verified && $emergency_file !== '') {
 $recoveryError = '';
 $recoveredSuccessfully = false;
 try {
 Logger::warning(sprintf(
 'CLI RESTORE RECOVERY BAŞLADI | job_id=%s | emergency_file=%s | original_error=%s',
 $job_id,
 $emergency_file,
 $e->getMessage()
 ));
 $recoveryConfig = $config;
 $recoveryConfig['analyze_after_restore'] = false;
 Logger::warning('CLI RESTORE RECOVERY: ana PDO bağlantısı kapatılıyor ve temiz bağlantı yeniden kuruluyor.');
 reconnect_restore_pdo_for_recovery($pdo, $recoveryConfig);
 perform_restore_cli_job(
 $pdo,
 $emergency_file,
 $backup_dir,
 $recoveryConfig,
 $lock_handle,
 $job_id,
 false
 );
 cleanup_emergency_backup_artifacts($backup_dir, $emergency_file);
 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'status' => 'failed',
 'recovered' => true,
 'percent' => 100,
 'file' => $file,
 'tables_count' => $tables_count,
 'rows_count' => $rows_count,
 'error' => $e->getMessage(),
 'recovery_message' => 'Restore başarısız oldu; restore öncesi CLI emergency snapshot başarıyla geri yüklendi.',
 'duration_seconds' => $restore_duration
 ]);
 $recoveredSuccessfully = true;
 Logger::warning(sprintf(
 'CLI RESTORE RECOVERY TAMAMLANDI | job_id=%s | original_file=%s | emergency_file=%s',
 $job_id, $file, $emergency_file
 ));
 } catch (Throwable $recoveryException) {
 $recoveryError = $recoveryException->getMessage();
 Logger::error(sprintf(
 'CLI RESTORE RECOVERY BAŞARISIZ | job_id=%s | emergency_file=%s | error=%s',
 $job_id,
 $emergency_file,
 $recoveryError
 ));
 }
 if ($recoveredSuccessfully) {
 throw new Exception('Restore başarısız oldu ancak eski veritabanı CLI emergency snapshot ile geri yüklendi: ' . $e->getMessage(), 0, $e);
 }
 if ($recoveryError !== '') {
 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'status' => 'failed',
 'recovered' => false,
 'recovery_required' => true,
 'percent' => min(99, $file_size > 0 ? (int)floor(($processed_bytes / $file_size) * 100) : 0),
 'file' => $file,
 'tables_count' => $tables_count,
 'rows_count' => $rows_count,
 'error' => $e->getMessage(),
 'recovery_error' => $recoveryError,
 'emergency_file' => $emergency_file,
 'duration_seconds' => $restore_duration
 ]);
 throw new Exception('Restore başarısız oldu ve eski veritabanının recovery işlemi de başarısız oldu. Emergency snapshot korunuyor: ' . $recoveryError, 0, $e);
 }
 }

 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'status' => 'failed',
 'recovered' => false,
 'percent' => min(99, $file_size > 0 ? (int)floor(($processed_bytes / $file_size) * 100) : 0),
 'file' => $file,
 'tables_count' => $tables_count,
 'rows_count' => $rows_count,
 'error' => $e->getMessage(),
 'emergency_file' => $emergency_file,
 'duration_seconds' => $restore_duration
 ]);

 Logger::error(sprintf(
 'RESTORE BAŞARISIZ | file=%s | status=failed | recovery=%s | tables=%d | rows=%d | duration=%ss | error=%s',
 $file,
 $emergency_file !== '' ? 'FAILED/KEPT' : ($restore_verified ? 'NOT_NEEDED' : 'NONE'),
 $tables_count,
 $rows_count,
 $restore_duration,
 $e->getMessage()
 ));

 throw $e;
 }
}
function resolve_cli_php_binary()
: string {
 $candidates = [];

 // Web SAPI'da PHP_BINARY çoğu sunucuda php-fpm/cgi binary'sini gösterebilir.
 // Arka plan işini mutlaka gerçek komut satırı PHP ile başlat.
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
// GÜVENLİK: Log dosyasına gerçek cron anahtarı yazılmaz; yalnızca komut yapısı kaydedilir.
function mask_cli_token_in_command(string $command, string $token)
: string {
 if ($token === '') return $command;
 return str_replace($token, '***CRON_TOKEN_MASKED***', $command);
}
/**
 * Uzun yedek ve geri yükleme işini ayrı bir komut satırı PHP işleminde başlatır. Tarayıcı kapanırsa bile iş devam edebilir.
 */

// =============================================================================
// PHP - ARKA PLAN CLI İŞİ BAŞLATMA

/*
NEDEN AYRI CLI SÜRECİ BAŞLATIYORUZ?
Panelin görevi kullanıcıya arayüz sağlamaktır.
Uzun yedekleme/geri yükleme ise uzun süren bir arka plan işidir.

Bu iki görevi ayırmak daha sağlıklı bir mimari oluşturur:

[ Web Paneli ]
 |
 | işi başlat
 v
[ CLI işçi süreç ]
 |
 +--> MySQL
 +--> Yedek dosyası
 +--> İlerleme / durum dosyası
 |
 v
[ Web Paneli ] ← sonucu gösterir

Böylece kullanıcı arayüzü ile uzun süren işlem birbirine
daha az bağımlı hale gelir.
*/

// Web panelinden başlatılan uzun işi ayrı bir PHP CLI süreci olarak çalıştırır.
// Böylece tarayıcı bağlantısı kapansa bile CLI işi devam edebilir.
// =============================================================================

function spawn_cli_job(
 string $script,
 string $backup_dir,
 string $token,
 string $job_type,
 string $job_id,
 string $file = ''
)
: bool {
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) return false;
 if (!in_array($job_type, ['backup', 'restore', 'integrity'], true)) return false;
 if (!is_dir($backup_dir)) return false;

 $admissionLock = acquire_job_admission_lock($backup_dir);
 if (!$admissionLock) return false;

 $reserved = false;

 try {
 // Aynı admission kilidi altında:
 // 1) Eski durum dosyalarını temizle
 // 2) aktif iş kontrolü yap
 // 3) Yeni iş durumunu atomik olarak rezerve et
 cleanup_stale_cli_job_states($backup_dir);
 assert_no_active_database_job($backup_dir, $job_id);
 reserve_cli_job_state($backup_dir, $job_id, $job_type, $file);
 $reserved = true;

 try {
 $capability = detect_cli_worker_capability();
 if (!$capability['available']) {
 $reason = (string)($capability['reason'] ?? 'CLI worker kullanılamıyor.');
 $missing = $capability['missing_extensions'] ?? [];
 if (is_array($missing) && $missing !== []) {
 $reason .= ' Eksik uzantılar: ' . implode(', ', array_map('strval', $missing));
 }
 throw new Exception($reason);
 }
 $php = (string)$capability['php_binary'];
 if ($php === '') {
 throw new Exception('Doğrulanmış CLI PHP binary bulunamadı.');
 }
 } catch (Throwable $e) {
 throw new Exception('CLI process başlatılamadı: ' . $e->getMessage(), 0, $e);
 }

 // Arka plan işçi sürecinin anahtarını işlem komut satırına yazma.
 // Sabit cron çağrısı aşağıda mevcut anahtar ile çalışmaya devam eder;
 // yalnızca web panelin başlattığı iç işçi süreci anahtarı ortam üzerinden taşınır.
 $args = [
 escapeshellarg($php),
 escapeshellarg($script),
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

 if (function_exists('exec')) {
 $output = [];
 $exitCode = 1;
 $oldWorkerToken = getenv('VEDO_WORKER_TOKEN');
 putenv('VEDO_WORKER_TOKEN=' . $token);
 try {
 @exec($cmd, $output, $exitCode);
 } finally {
 if ($oldWorkerToken === false) {
 putenv('VEDO_WORKER_TOKEN');
 } else {
 putenv('VEDO_WORKER_TOKEN=' . $oldWorkerToken);
 }
 }
 if ($exitCode === 0) {
 Logger::info("CLI {$job_type} job başlatıldı: {$job_id}");
 return true;
 }
 }

 if (function_exists('proc_open')) {
 $descriptor = [
 0 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'r'],
 1 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'a'],
 2 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'a'],
 ];
 $oldWorkerToken = getenv('VEDO_WORKER_TOKEN');
 putenv('VEDO_WORKER_TOKEN=' . $token);
 try {
 $process = @proc_open($cmd, $descriptor, $pipes);
 } finally {
 if ($oldWorkerToken === false) {
 putenv('VEDO_WORKER_TOKEN');
 } else {
 putenv('VEDO_WORKER_TOKEN=' . $oldWorkerToken);
 }
 }
 if (is_resource($process)) {
 $exitCode = @proc_close($process);
 if ($exitCode === 0) {
 Logger::info("CLI {$job_type} job başlatıldı (proc_open): {$job_id}");
 return true;
 }
 Logger::error("CLI {$job_type} job proc_open ile başlatıldı ancak süreç 0 olmayan çıkış kodu verdi: {$job_id} [exit={$exitCode}]");
 }
 }

 throw new Exception("CLI {$job_type} job başlatılamadı. exec/proc_open veya CLI PHP kontrol edilmeli.");
 } catch (Throwable $e) {
 if ($reserved) {
 // İşçi daha başlamadan başarısız olursa yer ayırma kaydı'ı sessizce silme.
 // Kullanıcıya ve temizleme sistemine işin hata ile bittiğini açıkça bildir.
 try {
 write_cli_job_state($backup_dir, $job_id, [
 'type' => $job_type,
 'engine' => 'cli',
 'status' => 'failed',
 'phase' => 'starting',
 'percent' => 0,
 'file' => $file,
 'recovered' => false,
 'recovery_required' => false,
 'error' => 'CLI worker başlatılamadı: ' . $e->getMessage()
 ]);
 } catch (Throwable $stateError) {
 Logger::error("CLI worker başarısızlık state'i yazılamadı | job_id=" . $job_id . " | error=" . $stateError->getMessage());
 $path = $backup_dir . '/.cli_job_' . $job_id . '.json';
 @unlink($path . '.tmp');
 @unlink($path);
 }
 }
 Logger::error("CLI {$job_type} job başlatılamadı | job_id={$job_id} | hata=" . $e->getMessage());
 return false;
 } finally {
 release_job_admission_lock($admissionLock);
 }
}


function run_cli_job_from_argv(array $argv, array $config, string $backup_dir)
: void {
 $job_type = '';
 $job_id = '';
 $file = '';

 foreach ($argv as $arg) {
 if (str_starts_with((string)$arg, '--job=')) $job_type = substr((string)$arg, 6);
 elseif (str_starts_with((string)$arg, '--job-id=')) $job_id = substr((string)$arg, 9);
 elseif (str_starts_with((string)$arg, '--file=')) $file = substr((string)$arg, 7);
 }

 if (!in_array($job_type, ['backup', 'restore', 'integrity'], true) || !preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 fwrite(STDERR, "ERROR: Geçersiz arka plan CLI işi.\n");
 exit(1);
 }

 clear_buffers();
 @set_time_limit(0);

 if (!VEDO_IS_CLI) {
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

 if ($job_type === 'integrity') {
 $state = read_cli_job_state($backup_dir, $job_id);
 if (!$state) { $state=['job_id'=>$job_id,'type'=>'integrity','engine'=>'cli']; }
 try {
 if (!is_string($file) || !validate_backup_filename($file) || is_emergency_backup_filename($file)) throw new Exception('Geçersiz bütünlük kontrolü dosyası.');
 $safe=validate_path_safe($backup_dir.'/'.$file,$backup_dir);
 $state['status']='running'; $state['phase']='integrity'; $state['percent']=5; $state['file']=$file; $state['current_table']='Checksum doğrulanıyor'; write_cli_job_state($backup_dir,$job_id,$state);
 $hash=verify_backup_checksum($safe);
 $state['percent']=50; $state['current_table']='SQL uyumluluğu taranıyor'; $state['backup_sha256']=$hash; write_cli_job_state($backup_dir,$job_id,$state);
 $validation=validate_backup_restore_compatibility($safe, false, (string)$config['db_name']);
 $state['status']='completed'; $state['phase']='completed'; $state['percent']=100; $state['current_table']='Tamamlandı'; $state['backup_sha256']=$hash; $state['restore_validation']=$validation; $state['message']='Bütünlük + test restore doğrulaması başarılı.'; write_cli_job_state($backup_dir,$job_id,$state); exit(0);
 } catch(Throwable $e) {
 $state['status']='failed'; $state['phase']='integrity'; $state['percent']=0; $state['error']=$e->getMessage(); write_cli_job_state($backup_dir,$job_id,$state); Logger::error('CLI INTEGRITY BAŞARISIZ | job_id='.$job_id.' | hata='.$e->getMessage()); exit(1);
 }
 }

 if ($job_type === 'backup') {
 $admission_lock = acquire_job_admission_lock($backup_dir);
 if (!$admission_lock) {
 $error = 'Job admission kilidi alınamadı.';
 write_cli_job_state($backup_dir, $job_id, ['type'=>'backup','status'=>'failed','percent'=>0,'error'=>$error]);
 Logger::error('CLI BACKUP BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $error);
 exit(1);
 }
 try {
 assert_restore_maintenance_marker_valid($backup_dir);
 assert_no_active_database_job($backup_dir, $job_id);
 } catch (Throwable $e) {
 release_job_admission_lock($admission_lock);
 write_cli_job_state($backup_dir, $job_id, ['type'=>'backup','status'=>'failed','percent'=>0,'error'=>$e->getMessage()]);
 Logger::error('CLI BACKUP BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $e->getMessage());
 exit(1);
 }
 $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $config['lock_timeout']);
 if (!$lock_handle) {
 $lockError = 'Başka bir veritabanı işlemi aktif veya ortak işlem kilidi alınamadı.';
 release_job_admission_lock($admission_lock);
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
 'engine' => 'cli',
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

 $progress_callback = static function (array $state) use ($backup_dir, $job_id, $job_started_at): void {
 $state['type'] = 'backup';
 $state['engine'] = 'cli';
 $state['job_started_at'] = $job_started_at;
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
 'engine' => 'cli',
 'status' => 'completed',
 'phase' => 'completed',
 'percent' => 100,
 'job_started_at' => $job_started_at,
 'file' => basename($file_path),
 'size' => $size,
 'duration_seconds' => max(0, $duration),
 'current_table' => 'Tamamlandı',
 'current_table_index' => (int)($final_state['total_tables'] ?? 0),
 'total_tables' => (int)($final_state['total_tables'] ?? 0),
 'processed_rows' => (int)($final_state['processed_rows'] ?? 0),
 'elapsed_seconds' => $duration,
 'estimated_remaining_seconds' => 0,
 'formatted_speed' => (string)($final_state['formatted_speed'] ?? ''),
 'speed_rows_per_second' => (int)($final_state['speed_rows_per_second'] ?? 0),
 'speed_mb_per_second' => (float)($final_state['speed_mb_per_second'] ?? 0),
 'bytes_written' => (int)($final_state['bytes_written'] ?? $size),
 'formatted_bytes' => format_bytes($size),
 'updated_at' => date('Y-m-d H:i:s')
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
 release_job_admission_lock($admission_lock);
 }
 exit(0);
 }

 $file = trim((string)$file);
 if (!validate_backup_filename($file)) {
 $error = 'Geçersiz restore dosyası.';
 write_cli_job_state($backup_dir, $job_id, ['type'=>'restore','status'=>'failed','percent'=>0,'error'=>$error]);
 Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | file=' . $file . ' | hata=' . $error);
 exit(1);
 }

 $admission_lock = acquire_job_admission_lock($backup_dir);
 if (!$admission_lock) {
 $error = 'Job admission kilidi alınamadı.';
 write_cli_job_state($backup_dir, $job_id, ['type'=>'restore','status'=>'failed','percent'=>0,'error'=>$error]);
 Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $error);
 exit(1);
 }
 try {
 assert_restore_maintenance_marker_valid($backup_dir, $job_id);
 assert_no_active_database_job($backup_dir, $job_id);
 } catch (Throwable $e) {
 release_job_admission_lock($admission_lock);
 write_cli_job_state($backup_dir, $job_id, ['type'=>'restore','status'=>'failed','percent'=>0,'error'=>$e->getMessage()]);
 Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $e->getMessage());
 exit(1);
 }
 $lock_handle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, $config['lock_timeout']);
 if (!$lock_handle) {
 release_job_admission_lock($admission_lock);
 $error = 'Başka bir veritabanı işlemi aktif veya ortak işlem kilidi alınamadı.';
 write_cli_job_state($backup_dir, $job_id, ['type'=>'restore','status'=>'failed','percent'=>0,'error'=>$error]);
 Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | hata=' . $error);
 exit(1);
 }

 $restoreCliStart = microtime(true);

 try {
 begin_restore_maintenance($backup_dir, $job_id, 'cli');
 Logger::info('CLI RESTORE İŞLEMİ BAŞLADI | job_id=' . $job_id . ' | file=' . $file . ' | db=' . $config['db_name']);
 $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name'], false, $config['use_persistent_pdo']);
 perform_restore_cli_job($pdo, $file, $backup_dir, $config, $lock_handle, $job_id);
 Logger::info(sprintf('CLI RESTORE İŞLEMİ TAMAMLANDI | job_id=%s | file=%s | duration=%ss', $job_id, $file, round(microtime(true)-$restoreCliStart,2)));
 } catch (Throwable $e) {
 $failureState = read_cli_job_state($backup_dir, $job_id) ?: [];
 $failureNeedsRecovery = ($failureState['type'] ?? '') === 'restore'
 && (
 !empty($failureState['recovery_required'])
 || (
 !empty($failureState['emergency_backup_completed'])
 && in_array((string)($failureState['phase'] ?? ''), ['clear_database', 'restore', 'analyze', 'analyze_pending'], true)
 )
 );
 $alreadyRecovered = ($failureState['type'] ?? '') === 'restore' && !empty($failureState['recovered']);
 if ($alreadyRecovered) {
 // perform_geri yükleme_cli_job emergency kurtarma başarılıysa, üst catch
 // bu sonucu normal bir başarısızlık durumu ile ezmemelidir.
 $failureState['status'] = 'failed';
 $failureState['recovered'] = true;
 $failureState['recovery_required'] = false;
 $failureState['recovery_message'] = (string)($failureState['recovery_message'] ?? 'Önceki veritabanı emergency snapshot ile geri yüklendi.');
 write_cli_job_state($backup_dir, $job_id, $failureState);
 } elseif ($failureNeedsRecovery) {
 try {
 mark_restore_maintenance_recovery_required($backup_dir, $job_id, 'CLI restore başarısız oldu ve recovery gerektiriyor: ' . $e->getMessage());
 } catch (Throwable $markerError) {
 Logger::error('CLI RESTORE RECOVERY MARKER YAZILAMADI | job_id=' . $job_id . ' | error=' . $markerError->getMessage());
 }
 } else {
 write_cli_job_state($backup_dir, $job_id, [
 'type' => 'restore',
 'status' => 'failed',
 'recovered' => false,
 'recovery_required' => false,
 'error' => $e->getMessage()
 ]);
 }
 Logger::error('CLI RESTORE BAŞARISIZ | job_id=' . $job_id . ' | file=' . $file . ' | duration=' . round(microtime(true)-$restoreCliStart,2) . 's | hata=' . $e->getMessage());
 exit(1);
 } finally {
 $finalState = read_cli_job_state($backup_dir, $job_id);
 $safeToRelease = is_array($finalState)
 && (($finalState['status'] ?? '') === 'completed' || !empty($finalState['recovered'])
 || (($finalState['status'] ?? '') === 'failed'
 && empty($finalState['recovery_required'])
 && empty($finalState['emergency_backup_completed'])));
 if ($safeToRelease) {
 end_restore_maintenance($backup_dir, $job_id);
 } else if ($finalState !== []) {
 try {
 mark_restore_maintenance_recovery_required($backup_dir, $job_id, 'CLI restore başarısız oldu; recovery tamamlanmadan bakım kilidi korunuyor.');
 } catch (Throwable $markerError) {
 Logger::error('CLI RESTORE FAILURE MARKER KORUNAMADI | job_id=' . $job_id . ' | error=' . $markerError->getMessage());
 }
 }
 release_system_lock($lock_handle);
 release_job_admission_lock($admission_lock);
 }
 exit(0);
}

$is_cli_sapi = VEDO_IS_CLI;
$has_cron_token = false;

if ($is_cli_sapi && isset($argv) && is_array($argv)) {
 foreach ($argv as $arg) {
 if (hash_equals($config['cron_token'], (string)$arg)) {
 $has_cron_token = true;
 break;
 }
 }
}

$workerToken = $is_cli_sapi ? (string)(getenv('VEDO_WORKER_TOKEN') ?: '') : '';
if (!$has_cron_token && $workerToken !== '' && hash_equals($config['cron_token'], $workerToken)) {
 $has_cron_token = true;
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

 // Cron ile WEB/CLI geri yükleme arasında admission + DB kilit sırası atomik tutulur.
 // Böylece restore durumunu kontrol etmeden yeni bir restore başlatılamaz.
 $cron_admission_lock = acquire_job_admission_lock($backup_dir);
 if (!$cron_admission_lock) {
 Logger::error('CRON BACKUP BAŞARISIZ | hata=Cron job admission kilidi alınamadı.');
 fwrite(STDERR, "ERROR: Job admission kilidi alinamadi.\n");
 exit(1);
 }

 $lock_handle = null;
 try {
 cleanup_stale_cli_job_states($backup_dir);
 assert_restore_maintenance_allows_action($backup_dir, 'run_full_backup');

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
 if ($lock_handle !== null) {
 release_system_lock($lock_handle);
 }
 }
 } catch (Throwable $e) {
 Logger::error('CRON BACKUP BAŞARISIZ | hata=' . $e->getMessage());
 fwrite(STDERR, "ERROR: " . $e->getMessage() . "\n");
 exit(1);
 } finally {
 release_job_admission_lock($cron_admission_lock);
 }
}

if (VEDO_IS_CLI) {
 fwrite(STDERR, "ERROR: Gecerli cron token verilmedi.\n");
 exit(1);
}

/**
 * Kalıcı giriş deneme sınırı durumu. Oturuma bağlı olmadığı için yeni oturum
 * açarak limitin aşılması engellenir. Sadece başarısız denemeleri kısa süre tutar.
 */
// İstek sınırı dosya anahtarı için kullanıcı adı ve IP SHA-256 ile özetlenir.
function get_login_rate_limit_keys(string $ip, string $username)
: array {
 $ip = substr($ip, 0, 128);
 $username = strtolower(trim($username));

 return [
 'combo' => hash('sha256', $ip . "\0" . $username),
 'ip' => hash('sha256', "ip\0" . $ip),
 'user' => hash('sha256', "user\0" . $username),
 ];
}
function read_login_rate_limit(string $backup_dir, string $key)
: array {
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
 'failures' => max(0, (int)($data['failures'] ?? 0)),
 'first_failure' => max(0, (int)($data['first_failure'] ?? 0)),
 'locked_until' => max(0, (int)($data['locked_until'] ?? 0)),
 ];
}
function write_login_rate_limit(string $backup_dir, string $key, array $state)
: void {
 $path = $backup_dir . '/.login_rate_' . $key . '.json';
 $tmp = $path . '.tmp';
 $json = json_encode([
 'failures' => max(0, (int)($state['failures'] ?? 0)),
 'first_failure' => max(0, (int)($state['first_failure'] ?? 0)),
 'locked_until' => max(0, (int)($state['locked_until'] ?? 0)),
 'updated_at' => time(),
 ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

 if (!safe_file_put_contents($tmp, $json, LOCK_EX) || !@rename($tmp, $path)) {
 @unlink($tmp);
 Logger::warning('Login rate-limit durumu yazılamadı.');
 }
}
function clear_login_rate_limit(string $backup_dir, string $key)
: void {
 $path = $backup_dir . '/.login_rate_' . $key . '.json';
 if (is_file($path)) {
 @unlink($path);
 }
}
function clear_login_rate_limit_all(string $backup_dir, string $ip, string $username)
: void {
 foreach (get_login_rate_limit_keys($ip, $username) as $key) {
 clear_login_rate_limit($backup_dir, $key);
 }
}
function cleanup_login_rate_limit_lock_files(string $backup_dir, int $max_age = 86400)
: void {
 $now = time();
 foreach (glob($backup_dir . '/.login_rate_*.lock') ?: [] as $lockPath) {
 if (!is_file($lockPath)) continue;
 $mtime = (int)@filemtime($lockPath);
 $age = $mtime > 0 ? max(0, $now - $mtime) : ($max_age + 1);
 if ($age <= $max_age) continue;
 $jsonPath = preg_replace('/\.lock$/', '.json', $lockPath);
 if (is_string($jsonPath) && is_file($jsonPath)) {
 $jsonMtime = (int)@filemtime($jsonPath);
 $jsonAge = $jsonMtime > 0 ? max(0, $now - $jsonMtime) : ($max_age + 1);
 if ($jsonAge <= $max_age) continue;
 }
 @unlink($lockPath);
 }
}


// =============================================================================
// PHP - GİRİŞ DENEMELERİNİ SINIRLAMA

/*
GİRİŞ GÜVENLİĞİ
Bu bölüm yanlış şifrelerin sınırsız denenmesini zorlaştırır.

Temel fikir:
Başarısız giriş → deneme sayısını artır → sınır aşılırsa
belirli süre beklet.

Bu, özellikle otomatik şifre deneme saldırılarını yavaşlatmak
için kullanılan basit bir savunmadır.
*/

// Çok sayıda başarısız giriş olduğunda hesabı/IP adresini geçici olarak kilitler.
// Bu mekanizma kaba kuvvet ile şifre tahmini yapılmasını zorlaştırır.
// =============================================================================

function enforce_login_rate_limit(string $backup_dir, string $ip, string $username, array $config)
: array {
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
 'locked' => $remaining > 0,
 'remaining' => $remaining,
 'keys' => $keys,
 'locked_by' => $lockedBy,
 ];
}
function register_login_failure_all(string $backup_dir, string $ip, string $username, array $config)
: array {
 $keys = get_login_rate_limit_keys($ip, $username);
 $limits = [
 'combo' => max(1, (int)($config['max_login_attempts'] ?? 5)),
 'ip' => max(1, (int)($config['max_ip_attempts'] ?? 20)),
 'user' => max(1, (int)($config['max_user_attempts'] ?? 10)),
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



// =============================================================================
// PHP - OTURUM VE GİRİŞ EKRANI

/*
OTURUM VE LOGIN AKIŞI
Kullanıcı daha paneli görmeden önce oturum kontrol edilir.

Basitleştirilmiş akış:
1) Session başlatılır.
2) CSRF anahtarı hazırlanır.
3) Giriş denemesi varsa kullanıcı adı/şifre kontrol edilir.
4) Güvenlik sorusu ve giriş denemesi sınırı uygulanır.
5) Başarılıysa session içine logged_in bilgisi yazılır.
6) Kullanıcı yönetim paneline alınır.

Session sayesinde kullanıcı her yeni istekte tekrar şifre girmek
zorunda kalmaz. CSRF anahtarı ise başka bir siteden kullanıcının
oturumu üzerinden istenmeyen form isteği gönderilmesini zorlaştırır.
*/

// Bu bölüm güvenli PHP oturumunu başlatır, CSRF anahtarını oluşturur, girişleri
// kontrol eder ve başarılı girişten sonra yönetim panelini açar.
// =============================================================================

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
 'httponly' => true,
 'secure' => is_request_https(),
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
 'expires' => time() - 42000,
 'path' => $params['path'],
 'domain' => $params['domain'],
 'secure' => $params['secure'],
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
 /*
 * ================================================================
 * LOGIN EKRANI
 * ================================================================
 * Bu ekran yalnızca "şifre soran bir form" değildir.
 * Aynı zamanda öğrenciye programın genel mimarisini gösteren
 * küçük bir giriş/ekranı olarak tasarlanmıştır.
 *
 * Kullanıcı giriş yapmadan önce:
 * - Bu dosyanın ne yaptığını,
 * - PHP / MySQL / HTML / CSS / JavaScript rollerini,
 * - CLI işçi süreç ile WEB işçi süreç arasındaki farkı,
 * - CLI'nin neden tercih edildiğini
 * görebilir.
 *
 * Bu bilgiler HTML/CSS tarafındadır; giriş doğrulamasını yapan
 * gerçek PHP kodu ise bu ekranın üst tarafında çalışır.
 * ================================================================
 */
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
 <title>VEDO MySQL Backup — ve Giriş</title>

 <!--
 LOGIN CSS
 Bu CSS, giriş ekranını iki ana bölüme ayırır:
 SOL = uygulamanın nasıl çalıştığını anlatan alanı
 SAĞ = gerçek giriş formu

 Böylece öğrenci login ekranında bile projenin mimarisini
 görsel olarak okuyabilir.
 -->
 <style>
 :root {
 --login-bg:#0b1020;
 --login-card:#111827;
 --login-card-2:#0f172a;
 --login-border:#263244;
 --login-text:#f8fafc;
 --login-muted:#a8b3c2;
 --login-accent:#4f9cff;
 --login-accent-2:#6ee7b7;
 --login-warn:#fbbf24;
 --login-danger:#fb7185;
 --login-input:#0b1220;
 --login-shadow:0 24px 70px rgba(0,0,0,.35);
 }

 html.theme-light {
 --login-bg:#eef3f8;
 --login-card:#ffffff;
 --login-card-2:#f8fafc;
 --login-border:#d7e0ea;
 --login-text:#16202b;
 --login-muted:#5d6b7a;
 --login-input:#ffffff;
 --login-shadow:0 24px 70px rgba(32,56,85,.13);
 }

 * { box-sizing:border-box; }

 body {
 margin:0;
 min-height:100vh;
 padding:28px;
 background:
 radial-gradient(circle at 10% 10%, rgba(79,156,255,.12), transparent 30%),
 radial-gradient(circle at 90% 80%, rgba(110,231,183,.08), transparent 28%),
 var(--login-bg);
 color:var(--login-text);
 font-family:<?= htmlspecialchars($config['ui_font'], ENT_QUOTES, 'UTF-8') ?>, system-ui, sans-serif;
 }

 .edu-shell {
 width:100%;
 max-width:1250px;
 margin:0 auto;
 }

 .edu-topbar {
 display:flex;
 justify-content:space-between;
 align-items:center;
 gap:16px;
 margin-bottom:18px;
 }

 .brand {
 font-size:20px;
 font-weight:800;
 letter-spacing:.2px;
 }

 .brand small {
 display:block;
 color:var(--login-muted);
 font-size:12px;
 font-weight:500;
 margin-top:3px;
 }

 .theme-toggle {
 border:1px solid var(--login-border);
 background:var(--login-card);
 color:var(--login-text);
 padding:9px 13px;
 border-radius:10px;
 cursor:pointer;
 }

 .edu-grid {
 display:grid;
 grid-template-columns:minmax(0, 1.65fr) minmax(320px, .8fr);
 gap:20px;
 align-items:start;
 }

 .edu-panel,
 .login-panel {
 background:var(--login-card);
 border:1px solid var(--login-border);
 border-radius:18px;
 box-shadow:var(--login-shadow);
 }

 .edu-panel { padding:26px; }
 .login-panel { padding:28px; position:sticky; top:20px; }

 .eyebrow {
 color:var(--login-accent);
 font-size:12px;
 font-weight:800;
 letter-spacing:.12em;
 text-transform:uppercase;
 margin-bottom:8px;
 }

 h1 {
 margin:0 0 10px;
 font-size:clamp(25px, 4vw, 38px);
 line-height:1.12;
 }

 .intro {
 margin:0 0 22px;
 color:var(--login-muted);
 line-height:1.65;
 max-width:850px;
 }

 .section-title {
 font-size:15px;
 font-weight:800;
 margin:22px 0 10px;
 }

 .flow {
 display:flex;
 flex-wrap:wrap;
 align-items:center;
 gap:8px;
 margin:12px 0 20px;
 }

 .flow-box {
 flex:1 1 130px;
 min-height:72px;
 padding:12px;
 border:1px solid var(--login-border);
 border-radius:12px;
 background:var(--login-card-2);
 }

 .flow-box strong {
 display:block;
 font-size:13px;
 margin-bottom:5px;
 }

 .flow-box span {
 color:var(--login-muted);
 font-size:11px;
 line-height:1.4;
 }

 .flow-arrow {
 color:var(--login-accent);
 font-weight:900;
 font-size:20px;
 }

 .workers {
 display:grid;
 grid-template-columns:1fr 1fr;
 gap:12px;
 }

 .worker-card {
 padding:16px;
 border:1px solid var(--login-border);
 border-radius:14px;
 background:var(--login-card-2);
 }

 .worker-card.cli { border-top:3px solid var(--login-accent-2); }
 .worker-card.web { border-top:3px solid var(--login-warn); }

 .worker-card h3 {
 margin:0 0 8px;
 font-size:15px;
 }

 .worker-card p {
 margin:0 0 9px;
 color:var(--login-muted);
 font-size:12px;
 line-height:1.55;
 }

 .worker-card ul {
 margin:8px 0 0;
 padding-left:18px;
 color:var(--login-muted);
 font-size:12px;
 line-height:1.55;
 }

 .recommend {
 margin-top:12px;
 padding:13px 15px;
 border-radius:12px;
 border:1px solid rgba(110,231,183,.35);
 background:rgba(110,231,183,.07);
 font-size:12px;
 line-height:1.55;
 }

 .recommend strong { color:var(--login-accent-2); }

 .tech-grid {
 display:grid;
 grid-template-columns:repeat(4, 1fr);
 gap:10px;
 margin-top:12px;
 }

 .tech {
 border:1px solid var(--login-border);
 border-radius:12px;
 padding:12px;
 background:var(--login-card-2);
 }

 .tech b { display:block; font-size:13px; margin-bottom:5px; }
 .tech span { color:var(--login-muted); font-size:11px; line-height:1.45; }

 .login-panel h2 {
 margin:0 0 7px;
 font-size:24px;
 }

 .login-subtitle {
 color:var(--login-muted);
 font-size:12px;
 line-height:1.5;
 margin-bottom:18px;
 }

 .login-note {
 padding:10px 12px;
 margin-bottom:16px;
 border-radius:10px;
 background:var(--login-card-2);
 border:1px solid var(--login-border);
 color:var(--login-muted);
 font-size:11px;
 line-height:1.5;
 }

 .error {
 background:rgba(251,113,133,.10);
 color:var(--login-danger);
 padding:10px 12px;
 border-radius:9px;
 font-size:12px;
 margin-bottom:15px;
 border:1px solid rgba(251,113,133,.28);
 }

 .form-group { margin-bottom:14px; }

 label {
 display:block;
 margin-bottom:6px;
 color:var(--login-muted);
 font-size:12px;
 font-weight:700;
 }

 input[type="text"],
 input[type="password"],
 input[type="number"] {
 width:100%;
 padding:11px 12px;
 border-radius:9px;
 border:1px solid var(--login-border);
 background:var(--login-input);
 color:var(--login-text);
 outline:none;
 }

 input:focus {
 border-color:var(--login-accent);
 box-shadow:0 0 0 3px rgba(79,156,255,.12);
 }

 .login-submit {
 width:100%;
 padding:12px;
 border:0;
 border-radius:9px;
 background:var(--login-accent);
 color:white;
 font-weight:800;
 cursor:pointer;
 margin-top:5px;
 }

 .login-submit:hover { filter:brightness(1.08); }

 .login-footer {
 margin-top:16px;
 color:var(--login-muted);
 font-size:10px;
 line-height:1.5;
 text-align:center;
 }

 @media (max-width:900px) {
 .edu-grid { grid-template-columns:1fr; }
 .login-panel { position:static; }
 }

 @media (max-width:650px) {
 body { padding:15px; }
 .workers { grid-template-columns:1fr; }
 .tech-grid { grid-template-columns:1fr 1fr; }
 .edu-panel, .login-panel { padding:20px; }
 }
 </style>
</head>
<body>
<div class="edu-shell">

 <!--
 ÜST BİLGİ
 Kullanıcı henüz giriş yapmadı. Bu nedenle burada uygulamanın
 adını ve olduğunu açıkça gösteriyoruz.
 -->
 <div class="edu-topbar">
 <div class="brand">
 VEDO MySQL Backup
 <small>Yönetim Paneli · Açıklamalı Sürüm</small>
 </div>
 <button type="button" class="theme-toggle" id="loginThemeToggle">☀ Açık Tema</button>
 </div>

 <div class="edu-grid">

 <!-- SOL: / MİMARİ ALANI -->
 <section class="edu-panel">
 <div class="eyebrow">Bu dosya ne yapıyor?</div>
 <h1>MySQL veritabanını yedekler, doğrular ve gerektiğinde geri yükler.</h1>
 <p class="intro">
 Bu tek PHP dosyası; MySQL bağlantısını, yedek alma ve geri yüklemeyi,
 dosya güvenliğini, oturum yönetimini, işlem kilitlerini, ilerleme takibini
 ve web arayüzünü birlikte yönetir. Aşağıdaki şema programı yukarıdan
 aşağıya anlamanıza yardımcı olur.
 </p>

 <div class="section-title">1. Genel çalışma şeması</div>
 <div class="flow">
 <div class="flow-box">
 <strong>👤 Kullanıcı</strong>
 <span>Butona basar, form gönderir veya durum ekranını izler.</span>
 </div>
 <div class="flow-arrow">→</div>
 <div class="flow-box">
 <strong>🖥️ JavaScript</strong>
 <span>Tarayıcıdaki olayları yönetir ve PHP'ye HTTP isteği gönderir.</span>
 </div>
 <div class="flow-arrow">→</div>
 <div class="flow-box">
 <strong>🐘 PHP</strong>
 <span>İsteği doğrular, güvenlik kontrollerini yapar ve işlemi başlatır.</span>
 </div>
 <div class="flow-arrow">→</div>
 <div class="flow-box">
 <strong>🗄️ MySQL / Disk</strong>
 <span>Veri okunur/yazılır; .sql.gz yedek dosyası oluşturulur.</span>
 </div>
 </div>

 <div class="section-title">2. PHP, HTML, CSS ve JavaScript görevleri</div>
 <div class="tech-grid">
 <div class="tech">
 <b>PHP</b>
 <span>Sunucuda çalışır. MySQL, dosya sistemi, oturum ve API işlemlerini yönetir.</span>
 </div>
 <div class="tech">
 <b>MySQL</b>
 <span>Tabloların ve diğer veritabanı nesnelerinin bulunduğu veri kaynağıdır.</span>
 </div>
 <div class="tech">
 <b>HTML + CSS</b>
 <span>Ekranın yapısını ve görünümünü oluşturur.</span>
 </div>
 <div class="tech">
 <b>JavaScript</b>
 <span>Tarayıcıdaki buton, form, ilerleme ve API iletişimini yönetir.</span>
 </div>
 </div>

 <div class="section-title">3. CLI Worker ve WEB Worker farkı</div>
 <div class="workers">
 <div class="worker-card cli">
 <h3>⚙️ CLI Worker — tercih edilen yöntem</h3>
 <p>
 PHP, panelden ayrı bir komut satırı süreci olarak uzun işi çalıştırır.
 Tarayıcı yalnızca işin durumunu izler.
 </p>
 <ul>
 <li>Uzun işlem HTTP isteğine doğrudan bağlı değildir.</li>
 <li>Tarayıcı kapansa bile iş normal şartlarda devam edebilir.</li>
 <li>Uzun yedekleme ve geri yükleme için daha uygundur.</li>
 </ul>
 </div>

 <div class="worker-card web">
 <h3>🌐 WEB Worker — alternatif yöntem</h3>
 <p>
 CLI çalıştırmaya izin vermeyen hostinglerde uzun iş küçük HTTP
 adımlarına bölünür.
 </p>
 <ul>
 <li>Tarayıcı belirli aralıklarla ilerleme isteği gönderir.</li>
 <li>Bu istekler sonraki iş adımlarını tetikleyebilir.</li>
 <li>Tarayıcı/polling durursa işin ilerlemesi de durabilir.</li>
 </ul>
 </div>
 </div>

 <div class="recommend">
 <strong>Neden CLI tavsiye ediliyor?</strong><br>
 Çünkü uzun süren yedekleme ve geri yükleme işlemlerini tarayıcı
 bağlantısından ayırır. WEB Worker ise özellikle CLI/exec/proc_open
 kullanılamayan paylaşımlı hosting ortamlarında uyumluluk amacıyla
 sunulan alternatif çalışma şeklidir.
 </div>

 <div class="section-title">4. Yedekleme işlemini zihinde canlandırın</div>
 <div class="flow">
 <div class="flow-box"><strong>① Kontrol</strong><span>Disk alanı, kilitler ve çalışma koşulları kontrol edilir.</span></div>
 <div class="flow-arrow">→</div>
 <div class="flow-box"><strong>② Oku</strong><span>Tablo yapısı ve veriler parça parça okunur.</span></div>
 <div class="flow-arrow">→</div>
 <div class="flow-box"><strong>③ Yaz</strong><span>SQL komutları sıkıştırılmış yedek dosyasına yazılır.</span></div>
 <div class="flow-arrow">→</div>
 <div class="flow-box"><strong>④ Doğrula</strong><span>Dosya ve SHA-256 bilgisi kontrol edilir.</span></div>
 </div>

 <div class="login-footer" style="text-align:left;">
 <b>İpucu:</b> Dosyayı incelerken önce bu ekranı, sonra PHP bölüm
 başlıklarını, ardından fonksiyonların üstündeki “” açıklamalarını
 okuyun. Son olarak JavaScript'in hangi PHP API çağrısını yaptığını takip edin.
 </div>
 </section>

 <!-- SAĞ: GERÇEK LOGIN FORMU -->
 <aside class="login-panel">
 <div class="eyebrow">Yetkili erişim</div>
 <h2>Panel Girişi</h2>
 <div class="login-subtitle">
 Yönetim panelini açmak için kullanıcı adı, şifre ve güvenlik sorusunu
 tamamlayın.
 </div>

 <div class="login-note">
 <b>Güvenlik:</b> Bu form POST ile gönderilir. CSRF kontrolü,
 giriş denemesi sınırı ve session tabanlı oturum kontrolü PHP tarafında yapılır.
 </div>

 <?php if (!empty($err)): ?>
 <div class="error"><?= htmlspecialchars($err, ENT_QUOTES, 'UTF-8') ?></div>
 <?php endif; ?>

 <form method="POST">
 <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') ?>">

 <div class="form-group">
 <label for="login_username">Kullanıcı Adı</label>
 <input id="login_username" type="text" name="username" required autofocus autocomplete="username">
 </div>

 <div class="form-group">
 <label for="login_password">Şifre</label>
 <input id="login_password" type="password" name="password" required autocomplete="current-password">
 </div>

 <div class="form-group">
 <label for="login_captcha">Güvenlik Sorusu: <?= $num1 ?> + <?= $num2 ?> = ?</label>
 <input id="login_captcha" type="number" name="captcha" required inputmode="numeric" autocomplete="off">
 </div>

 <button type="submit" class="login-submit">Giriş Yap ve Panele Geç</button>
 </form>

 <div class="login-footer">
 Bu ekranın açıklamaları dır.<br>
 Gerçek işlemler girişten sonra PHP tarafından yürütülür.
 </div>
 </aside>
 </div>
</div>

<!--
LOGIN JAVASCRIPT
Buradaki JavaScript veritabanı işlemi yapmaz.
Sadece açık/koyu tema seçimini kullanıcı tarayıcısında saklar.
Asıl giriş doğrulaması PHP tarafındadır.
-->
<script nonce="<?= $nonce ?>">
(() => {
 const key = 'vedo_theme';
 const saved = localStorage.getItem(key);
 const defaultTheme = '<?= $config['ui_default_theme'] === 'light' ? 'light' : 'dark' ?>';
 const theme = saved === 'light' || saved === 'dark' ? saved : defaultTheme;
 const root = document.documentElement;
 const button = document.getElementById('loginThemeToggle');

 const applyTheme = (value) => {
 root.classList.toggle('theme-light', value === 'light');
 root.classList.toggle('theme-dark', value === 'dark');
 if (button) {
 button.textContent = value === 'dark' ? '☀ Açık Tema' : '☾ Koyu Tema';
 }
 };

 applyTheme(theme);

 button?.addEventListener('click', () => {
 const next = root.classList.contains('theme-dark') ? 'light' : 'dark';
 localStorage.setItem(key, next);
 applyTheme(next);
 });
})();
</script>
</body>
</html>
<?php
 exit;
}

/**
 * Linux ve varsa container kaynaklarını okur. Böylece kullanılabilecek gerçek kapasiteyi öğrenir.
 */
function read_first_existing_file(array $paths)
: ?string {
 foreach ($paths as $path) {
 if (!is_readable($path)) continue;
 $value = @file_get_contents($path);
 if ($value !== false) return trim($value);
 }
 return null;
}

function parse_cgroup_cpu_quota_cores()
: ?float {
 $v2 = read_first_existing_file([
 '/sys/fs/cgroup/cpu.max',
 ]);
 if ($v2 !== null && $v2 !== '') {
 $parts = preg_split('/\s+/', $v2);
 if (count($parts) >= 2 && ($parts[0] ?? '') !== 'max') {
 $quota = (float)$parts[0];
 $period = (float)$parts[1];
 if ($quota > 0 && $period > 0) return max(0.01, $quota / $period);
 }
 }

 $quota = read_first_existing_file([
 '/sys/fs/cgroup/cpu/cpu.cfs_quota_us',
 '/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us',
 ]);
 $period = read_first_existing_file([
 '/sys/fs/cgroup/cpu/cpu.cfs_period_us',
 '/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us',
 ]);
 if ($quota !== null && $period !== null && is_numeric($quota) && is_numeric($period)) {
 $quotaValue = (float)$quota;
 $periodValue = (float)$period;
 if ($quotaValue > 0 && $periodValue > 0) return max(0.01, $quotaValue / $periodValue);
 }

 return null;
}

function count_cpu_list(string $list)
: int {
 $count = 0;
 foreach (preg_split('/,/', trim($list)) ?: [] as $part) {
 $part = trim($part);
 if ($part === '') continue;
 if (str_contains($part, '-')) {
 [$start, $end] = array_map('intval', explode('-', $part, 2));
 if ($end >= $start) $count += ($end - $start + 1);
 } elseif (ctype_digit($part)) {
 $count++;
 }
 }
 return max(0, $count);
}

function get_effective_cpu_capacity()
: array {
 $online = get_cpu_core_count();
 $cpusetRaw = read_first_existing_file([
 '/sys/fs/cgroup/cpuset.cpus.effective',
 '/sys/fs/cgroup/cpuset.cpus',
 '/sys/fs/cgroup/cpuset/cpuset.cpus',
 ]);
 $cpusetCount = $cpusetRaw !== null ? count_cpu_list($cpusetRaw) : 0;
 $cpusetCount = $cpusetCount > 0 ? $cpusetCount : $online;

 $quotaCores = parse_cgroup_cpu_quota_cores();
 $capacity = $quotaCores !== null ? min((float)$cpusetCount, $quotaCores) : (float)$cpusetCount;
 if ($capacity <= 0) $capacity = max(1, $online);

 return [
 'cores' => max(1, (int)ceil($capacity)),
 'capacity_cores' => $capacity,
 'online_cores' => max(1, $online),
 'quota_cores' => $quotaCores,
 'cpuset_cores' => $cpusetCount,
 ];
}

function read_cgroup_memory_stats()
: ?array {
 $limitRaw = read_first_existing_file([
 '/sys/fs/cgroup/memory.max',
 ]);
 $currentRaw = read_first_existing_file([
 '/sys/fs/cgroup/memory.current',
 ]);
 $limit = null;
 $current = null;

 if ($limitRaw !== null && $limitRaw !== '' && $limitRaw !== 'max' && is_numeric($limitRaw)) {
 $candidate = (int)$limitRaw;
 if ($candidate > 0 && $candidate < PHP_INT_MAX) $limit = $candidate;
 }
 if ($currentRaw !== null && $currentRaw !== '' && is_numeric($currentRaw)) {
 $candidate = (int)$currentRaw;
 if ($candidate >= 0) $current = $candidate;
 }

 if ($limit === null) {
 $limitV1 = read_first_existing_file([
 '/sys/fs/cgroup/memory/memory.limit_in_bytes',
 ]);
 $currentV1 = read_first_existing_file([
 '/sys/fs/cgroup/memory/memory.usage_in_bytes',
 ]);
 if ($limitV1 !== null && is_numeric($limitV1)) {
 $candidate = (int)$limitV1;
 // cgroup v1 gerçek bir sınır yoksa çok büyük bir işaret değeri kullanır.
 if ($candidate > 0 && $candidate < (PHP_INT_MAX >> 2)) $limit = $candidate;
 }
 if ($currentV1 !== null && is_numeric($currentV1)) {
 $candidate = (int)$currentV1;
 if ($candidate >= 0) $current = $candidate;
 }
 }

 if ($limit === null && $current === null) return null;
 return [
 'limit_bytes' => $limit,
 'current_bytes' => $current,
 'source' => $limit !== null ? 'cgroup' : 'cgroup-current-only'
 ];
}

function get_accurate_ram_metrics()
: array {
 $memInfo = read_proc_meminfo_kb(0);
 $procTotal = (int)($memInfo['MemTotal'] ?? 0) * 1024;
 $procAvailable = (int)($memInfo['MemAvailable'] ?? 0) * 1024;

 $cgroup = read_cgroup_memory_stats();
 $total = $procTotal;
 $used = max(0, $procTotal - $procAvailable);
 $free = $procAvailable;
 $source = 'proc-meminfo';

 if ($cgroup !== null) {
 $limit = (int)($cgroup['limit_bytes'] ?? 0);
 $current = $cgroup['current_bytes'];
 if ($limit > 0) {
 // Kullanılabilir RAM, görünen RAM ile cgroup limitinin küçük olanıdır.
 $total = $procTotal > 0 ? min($procTotal, $limit) : $limit;
 $source = 'cgroup+proc-meminfo';
 if ($current !== null) {
 $used = min($total, max(0, (int)$current));
 $free = max(0, $total - $used);
 } else {
 $used = min($total, max(0, $total - $procAvailable));
 $free = max(0, $total - $used);
 }
 }
 }

 // RAM bilgisi tam alınamazsa güvenli geri dönüş kullanılır.
 if ($total <= 0) {
 $available = get_available_server_memory_bytes();
 $total = $available > 0 ? $available : 0;
 $used = 0;
 $free = $total;
 $source = 'fallback';
 }

 return [
 'total' => max(0, (int)$total),
 'used' => max(0, min((int)$total, (int)$used)),
 'free' => max(0, min((int)$total, (int)$free)),
 'percent' => $total > 0 ? round(($used / $total) * 100, 1) : 0,
 'source' => $source,
 ];
}

function read_cgroup_cpu_usage_usec()
: ?int {
 $raw = read_first_existing_file(['/sys/fs/cgroup/cpu.stat']);
 if ($raw !== null) {
 foreach (preg_split('/\R/', $raw) ?: [] as $line) {
 if (preg_match('/^usage_usec\s+(\d+)$/', trim($line), $m)) return (int)$m[1];
 }
 }
 $rawV1 = read_first_existing_file(['/sys/fs/cgroup/cpuacct/cpuacct.usage', '/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage']);
 if ($rawV1 !== null && is_numeric($rawV1)) return (int)floor(((float)$rawV1) / 1000.0);
 return null;
}

function get_cpu_metrics_accurate(int $sampleMs = 120)
: array {
 $capacity = get_effective_cpu_capacity();
 $usage1 = read_cgroup_cpu_usage_usec();
 if ($usage1 !== null) {
 $sampleStartedAt = microtime(true);
 usleep(max(50000, min(500000, $sampleMs * 1000)));
 $usage2 = read_cgroup_cpu_usage_usec();
 $elapsedSec = max(0.001, microtime(true) - $sampleStartedAt);
 if ($usage2 !== null && $usage2 >= $usage1) {
 $cpuSeconds = ($usage2 - $usage1) / 1000000.0;
 $capacitySeconds = max(0.001, $capacity['capacity_cores'] * $elapsedSec);
 $percent = ($cpuSeconds / $capacitySeconds) * 100.0;
 $loads = function_exists('sys_getloadavg') ? sys_getloadavg() : [0,0,0];
 return [
 'percent' => round(min(100, max(0, $percent)), 1),
 'load_1min' => round((float)($loads[0] ?? 0), 2),
 'load_5min' => round((float)($loads[1] ?? 0), 2),
 'load_15min' => round((float)($loads[2] ?? 0), 2),
 'cores' => $capacity['cores'],
 'capacity_cores' => $capacity['capacity_cores'],
 'source' => 'cgroup-cpu.stat'
 ];
 }
 }

 // cgroup CPU bilgisi yoksa /proc/stat kullanılır.
 $first = read_cpu_proc_stat();
 $loads = function_exists('sys_getloadavg') ? sys_getloadavg() : [0,0,0];
 if ($first !== null) {
 $sampleStartedAt = microtime(true);
 usleep(max(50000, min(500000, $sampleMs * 1000)));
 $second = read_cpu_proc_stat();
 $elapsedSec = max(0.001, microtime(true) - $sampleStartedAt);
 if ($second !== null) {
 $totalDelta = $second['total'] - $first['total'];
 $busyDelta = $second['busy'] - $first['busy'];
 if ($totalDelta > 0 && $busyDelta >= 0) {
 return [
 'percent' => round(min(100, max(0, ($busyDelta / $totalDelta) * 100)), 1),
 'load_1min' => round((float)($loads[0] ?? 0), 2),
 'load_5min' => round((float)($loads[1] ?? 0), 2),
 'load_15min' => round((float)($loads[2] ?? 0), 2),
 'cores' => $capacity['cores'],
 'capacity_cores' => $capacity['capacity_cores'],
 'source' => '/proc/stat'
 ];
 }
 }
 }

 $fallback = $capacity['capacity_cores'] > 0 ? ((float)($loads[0] ?? 0) / $capacity['capacity_cores']) * 100 : 0;
 return [
 'percent' => round(min(100, max(0, $fallback)), 1),
 'load_1min' => round((float)($loads[0] ?? 0), 2),
 'load_5min' => round((float)($loads[1] ?? 0), 2),
 'load_15min' => round((float)($loads[2] ?? 0), 2),
 'cores' => $capacity['cores'],
 'capacity_cores' => $capacity['capacity_cores'],
 'source' => 'loadavg-fallback'
 ];
}

/**
 * CPU sayaçlarını kısa süre ölçer ve gerçek CPU kullanım yüzdesini hesaplar. %100 tüm kapasitenin dolu olduğunu gösterir.
 */
function read_cpu_proc_stat()
: ?array {
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

function get_cpu_core_count()
: int {
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

function get_instant_cpu_metrics(int $sampleMs = 120)
: array {
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
 $sampleStartedAt = microtime(true);
 usleep(max(50000, min(500000, $sampleMs * 1000)));
 $second = read_cpu_proc_stat();
 $elapsedSec = max(0.001, microtime(true) - $sampleStartedAt);

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

 // /proc/stat yoksa load average son çare olarak kullanılır.
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

/**
 * Panel için CPU, RAM ve disk bilgilerini toplar. Okunamayan bilgi için güvenli bir geri dönüş kullanır.
 */

// =============================================================================
// PHP - SUNUCU İZLEME VERİLERİ
// Dashboard'da görülen CPU, RAM, disk ve benzeri kaynak bilgilerini toplar.
// =============================================================================

function get_server_metrics(array $config, string $backup_dir)
: array {
 // Aynı sistem bilgilerini bu istekte defalarca okumamak için bir kez hesaplanır.
 $hostname = gethostname() ?: 'N/A';
 $kernel = php_uname('r');
 $machine = php_uname('m');
 $metrics = [
 'hostname' => $hostname,
 'os' => PHP_OS_FAMILY . ' (' . $kernel . ')',
 'php_version' => PHP_VERSION,
 'php_sapi' => PHP_SAPI,
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
 'percent' => 0,
 'source' => 'unknown'
 ],
 'disk' => [
 'total' => 0,
 'used' => 0,
 'free' => 0,
 'percent' => 0,
 'source' => 'disk_total_space'
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
 'extensions_count' => 0
 ],
 'php_extensions' => [],
 'mysql' => [
 'server_version' => 'N/A',
 'client_version' => 'N/A',
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
 'hostname' => $hostname,
 'os' => PHP_OS_FAMILY,
 'kernel' => $kernel,
 'machine' => $machine,
 'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'CLI/Unknown',
 'server_protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'N/A',
 'https' => is_request_https() ? 'ON' : 'OFF',
 'server_ip' => $_SERVER['SERVER_ADDR'] ?? gethostbyname($hostname !== 'N/A' ? $hostname : 'localhost'),
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

 static $phpExtensions = null;
 if ($phpExtensions === null) {
 $phpExtensions = get_loaded_extensions();
 }
 $metrics['php_extensions'] = $phpExtensions;
 $metrics['php_env']['extensions_count'] = count($phpExtensions);
 $resourceProfile = get_dynamic_resource_profile($backup_dir);
 $metrics['resources'] = [
 'ram_total' => (int)$resourceProfile['ram_total_bytes'],
 'ram_free' => (int)$resourceProfile['ram_free_bytes'],
 'ram_used_percent' => (float)$resourceProfile['ram_used_percent'],
 'operation_ram_budget' => (int)$resourceProfile['operation_ram_budget_bytes'],
 'cpu_pressure_percent' => (float)$resourceProfile['cpu_pressure_percent'],
 'cpu_capacity_cores' => (float)$resourceProfile['cpu_capacity_cores'],
 'disk_total' => (int)$resourceProfile['disk_total_bytes'],
 'disk_free' => (int)$resourceProfile['disk_free_bytes'],
 'disk_safety' => (int)$resourceProfile['disk_safety_bytes']
 ];

 // CPU kullanımı önce cgroup bilgisinden, yoksa /proc/stat üzerinden alınır.
 $cpu = get_cpu_metrics_accurate(120);
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

 // RAM: VDS veya container limiti varsa gerçek kullanılabilir sınır kullanılır.
 $ram = get_accurate_ram_metrics();
 $metrics['ram']['total'] = $ram['total'];
 $metrics['ram']['used'] = $ram['used'];
 $metrics['ram']['free'] = $ram['free'];
 $metrics['ram']['percent'] = $ram['percent'];
 $metrics['ram']['source'] = $ram['source'];

 // Disk.
 $disk_free = @disk_free_space($backup_dir);
 $disk_total = @disk_total_space($backup_dir);
 if ($disk_free !== false && $disk_total !== false && $disk_total > 0) {
 $disk_used = $disk_total - $disk_free;
 $metrics['disk']['total'] = $disk_total;
 $metrics['disk']['used'] = $disk_used;
 $metrics['disk']['free'] = $disk_free;
 $metrics['disk']['percent'] = round(($disk_used / $disk_total) * 100);
 $metrics['disk']['source'] = 'filesystem:' . $backup_dir;
 }

 // Yedek klasörünü tek geçişte tarayarak boyut, adet ve son yedeği hesapla.
 $b_size = 0;
 $b_count = 0;
 $latestBackup = null;
 if (is_dir($backup_dir)) {
 try {
 foreach (new DirectoryIterator($backup_dir) as $fileinfo) {
 if (!$fileinfo->isFile() || !str_ends_with($fileinfo->getFilename(), '.sql.gz') || is_emergency_backup_filename($fileinfo->getFilename())) continue;

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

 // MySQL sürümü ve veri tabanı özeti
 try {
 $pdo = get_pdo($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
 $metrics['mysql_version'] = $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) ?: 'N/A';
 $metrics['mysql']['server_version'] = $metrics['mysql_version'];
 $metrics['mysql']['client_version'] = 'N/A';
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
 // Extension listesi yukarıda önbellek'lendi; burada tekrar PHP'den okumaya gerek yok.
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

// 9. veri tabanı GEZGİNİ YARDIMCILARI
function is_db_identifier_safe(string $name)
: bool {
 if ($name === '' || str_contains($name, "\0") || str_contains($name, '`')) {
 return false;
 }
 if (!vedo_utf8_valid($name)) {
 return false;
 }
 if (preg_match('/[\\x00-\\x1F\\x7F]/u', $name)) {
 return false;
 }
 return vedo_utf8_strlen($name) <= 64;
}

function validate_db_identifier(string $name)
: string {
 if (!is_db_identifier_safe($name)) {
 throw new Exception('Geçersiz veritabanı veya tablo adı.');
 }
 return $name;
}
function get_database_tables(PDO $pdo, string $db_name)
: array {
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
function get_table_structure(PDO $pdo, string $db_name, string $table)
: array {
 $table = validate_db_identifier($table);
 $stmt = $pdo->prepare("SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, COLUMN_DEFAULT, EXTRA, COLLATION_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION");
 $stmt->execute([$db_name, $table]);
 $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
 $stmt->closeCursor();
 return $columns;
}


function get_table_preview(PDO $pdo, string $db_name, string $table, int $limit = 100, int $offset = 0)
: array {
 $table = validate_db_identifier($table);
 $limit = max(1, min(100, $limit));
 $offset = max(0, $offset);
 $orderBy = get_table_fallback_order_by($pdo, $db_name, $table);
 $stmt = $pdo->query("SELECT * FROM `{$table}` ORDER BY {$orderBy} LIMIT {$offset}, {$limit}");
 $rows = $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
 if ($stmt) $stmt->closeCursor();
 return ['rows' => $rows, 'offset' => $offset, 'limit' => $limit];
}
/**
 * Seçilen tablo üzerinde yalnızca izin verilen bakım işlemini çalıştırır.
 * Tablo adı ve işlem türü çalıştırmadan önce ayrı güvenlik kontrollerinden geçirilir.
 */

// =============================================================================
// PHP - TABLO YÖNETİMİ
// Tablo listeleme, yapı/önizleme, bakım, TRUNCATE ve DROP gibi işlemler bu bölümde
// kontrol edilir. Tehlikeli işlemler ortak veri tabanı kilidiyle korunur.
// =============================================================================

function perform_table_maintenance(PDO $pdo, string $db_name, string $table, string $operation)
: string {
 $table = validate_db_identifier($table);
 $operation = strtolower(trim($operation));
 $allowed = ['analyze' => 'ANALYZE TABLE', 'repair' => 'REPAIR TABLE', 'optimize' => 'OPTIMIZE TABLE'];
 if (!isset($allowed[$operation])) throw new Exception('Geçersiz bakım işlemi.');

 if ($operation === 'repair') {
 $engineStmt = $pdo->prepare("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? LIMIT 1");
 $engineStmt->execute([$db_name, $table]);
 $engine = strtoupper((string)($engineStmt->fetchColumn() ?? ''));
 $engineStmt->closeCursor();
 if ($engine !== 'MYISAM') {
 throw new Exception("REPAIR TABLE yalnızca MyISAM tablolarında kullanılabilir. Mevcut motor: {$engine}");
 }
 }

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
function truncate_table(PDO $pdo, string $table)
: void {
 $table = validate_db_identifier($table);
 $pdo->exec("TRUNCATE TABLE `{$table}`");
 Logger::warning("Tablo boşaltıldı: {$table}");
}
function drop_table(PDO $pdo, string $table)
: void {
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
 'php_info',
 'clear_logs',
 'get_system_logs',
 'log_stream',
 'get_cli_job_progress',
 'get_active_cli_jobs',
 'read_cli_job_state',
 'get_worker_capabilities',
 'db_tables',
 'db_table_data',
 'db_table_structure',
 'db_table_maintenance',
 'db_table_truncate',
 'db_table_drop',
 'import_sql_upload',
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

 // Veri değiştiren işlemlerde güvenlik doğrulaması (CSRF) zorunludur.
 // log_stream sadece giriş yapmış kullanıcının loglarını okur. Tarayıcı bu istekte özel güvenlik başlığı gönderemediği için
 // güvenlik token'ını URL'ye koymuyoruz. Diğer işlemlerde token sadece güvenlik başlığı veya POST verisiyle kabul edilir.
 if ($action !== 'log_stream') {
 $request_csrf = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? '');
 if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $request_csrf)) {
 json_response(false, 'Güvenlik Doğrulaması (CSRF) Başarısız!', [], 403);
 }
 }

 try {
 assert_restore_maintenance_allows_action($backup_dir, (string)$action);
 } catch (Throwable $maintenanceError) {
 json_response(false, $maintenanceError->getMessage(), [], 409);
 }

 // Canlı sistem bilgilerini veritabanına bağlanmadan göster.
 if ($action === 'live_metrics') {
 $cpuLive = get_cpu_metrics_accurate(VEDO_LIVE_METRICS_SAMPLE_MS);
 $cpuPercent = (float)$cpuLive['percent'];
 $cpuCores = (int)$cpuLive['cores'];
 $load1 = (float)$cpuLive['load_1min'];
 $load5 = (float)$cpuLive['load_5min'];
 $load15 = (float)$cpuLive['load_15min'];

 $ramLive = get_accurate_ram_metrics();
 $ramTotal = (int)$ramLive['total'];
 $ramUsed = (int)$ramLive['used'];
 $ramAvailable = (int)$ramLive['free'];
 $ramPercent = (float)$ramLive['percent'];

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
 'capacity_cores' => (float)($cpuLive['capacity_cores'] ?? $cpuCores),
 'sample_ms' => VEDO_LIVE_METRICS_SAMPLE_MS,
 'source' => (string)$cpuLive['source']
 ],
 'ram' => [
 'percent' => $ramPercent,
 'used' => $ramUsed,
 'total' => $ramTotal,
 'free' => $ramAvailable,
 'source' => (string)$ramLive['source']
 ],
 'disk' => [
 'percent' => $diskPercent,
 'used' => $diskUsed,
 'total' => $diskTotal,
 'free' => $diskFree !== false ? $diskFree : 0,
 'source' => 'filesystem:' . $diskPath
 ]
 ]);
 }
 try {
 $pdo = init_pdo_with_dynamic_memory($config);

 if ($action === 'db_tables') {
 json_response(true, 'Tablolar listelendi.', ['tables' => get_database_tables($pdo, $config['db_name']), 'database' => $config['db_name']]);
 }

 if ($action === 'import_sql_upload') {
 require_post();

 if (!isset($_FILES['sql_file']) || !is_array($_FILES['sql_file'])) {
 json_response(false, 'SQL dosyası seçilmedi.', [], 400);
 }

 $admissionLock = acquire_job_admission_lock($backup_dir);
 if (!$admissionLock) {
 json_response(false, 'Başka bir veritabanı işlemi başlatılıyor. SQL içeri aktarma başlatılamaz.', [], 409);
 }
 assert_restore_maintenance_marker_valid($backup_dir);
 assert_no_active_database_job($backup_dir);
 $lockHandle = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, (int)$config['lock_timeout']);
 if (!$lockHandle) {
 release_job_admission_lock($admissionLock);
 json_response(false, 'Başka bir veritabanı işlemi aktif. SQL içeri aktarma başlatılamaz.', [], 409);
 }

 $importReport = null;
 $importError = null;
 try {
 require_database_operation_lock($lockHandle, $backup_dir);
 update_system_lock_heartbeat($lockHandle);

 $importMode = strtolower(trim((string)($_POST['import_mode'] ?? 'safe')));
 if (!in_array($importMode, ['safe', 'soft'], true)) {
 throw new Exception('Geçersiz SQL import modu.');
 }
 $recoveryReport = [];
 $importReport = import_uploaded_sql_file($pdo, $_FILES['sql_file'], $config['db_name'], $importMode, $recoveryReport);
 update_system_lock_heartbeat($lockHandle);
 } catch (Throwable $e) {
 $importError = $e;
 Logger::error('SQL IMPORT BAŞARISIZ | db=' . $config['db_name'] . ' | error=' . $e->getMessage());
 } finally {
 release_system_lock($lockHandle);
 release_job_admission_lock($admissionLock);
 }

 if ($importError instanceof Throwable) {
 json_response(false, 'SQL içeri aktarma başlatılamadı: ' . $importError->getMessage(), [], 500);
 }

 $hasErrors = ((int)$importReport['errors']) > 0 || ((int)($importReport['blocked'] ?? 0)) > 0;
 $modeLabel = (($importReport['import_mode'] ?? 'safe') === 'soft') ? 'Yumuşak Import' : 'Güvenli Import';
 if (($recoveryReport['status'] ?? '') === 'RECOVERED') {
 json_response(false, 'Yumuşak Import başarısız oldu; değişiklikler import öncesi snapshot üzerinden geri alındı.', $importReport, 422);
 }
 json_response(
 true,
 $hasErrors
 ? "{$modeLabel} tamamlandı; bazı sorgular güvenlik nedeniyle engellendi veya hata verdi."
 : "{$modeLabel} başarıyla tamamlandı.",
 $importReport
 );
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
 'web_fallback_available' => true,
 'web_backup_available' => true,
 'web_restore_available' => true,
 'background_worker_required' => false
 ]);
 }

 // Varsayılan seçim CLI'dir; WEB seçilirse Web işçi süreci zorunlu olarak kullanılır.
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
 if (spawn_cli_job(__FILE__, $backup_dir, $config['cron_token'], 'backup', $job_id)) {
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
 try {
 $state = initialize_web_backup_job($pdo, $backup_dir, $config, $job_id);
 } catch (Throwable $e) {
 json_response(false, $e->getMessage(), ['engine' => 'web', 'job_id' => $job_id], 409);
 }
 json_response(true, 'Web Worker yedekleme başlatıldı.', [
 'status' => $state['status'],
 'job_id' => $job_id,
 'engine' => 'web',
 'message' => 'Web Worker ile yedekleme adım adım yürütülecek. WEB modu veritabanı genelinde tek zamanlı snapshot garanti etmez.'
 ]);
 }

 if ($action === 'get_active_cli_jobs') {
 require_post();
 cleanup_stale_cli_job_states($backup_dir);
 json_response(true, 'Aktif CLI işler alındı.', [
 'jobs' => find_active_cli_job_states($backup_dir)
 ]);
 }

 if ($action === 'read_cli_job_state') {
 require_post();
 $job_id = (string)($_POST['job_id'] ?? '');
 if (!preg_match('/^[a-f0-9]{32}$/', $job_id)) {
 json_response(false, 'Geçersiz CLI job ID.', [], 400);
 }
 $state = read_cli_job_state($backup_dir, $job_id);
 json_response(true, 'Job durumu okundu.', $state ?: [
 'status' => 'starting',
 'percent' => 0,
 'job_id' => $job_id
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

 // WEB işçi süreci işlerinde her ilerleme sorgusu aynı zamanda bir küçük işlem adımıdır.
 if (
 ($state['engine'] ?? 'cli') === 'web' &&
 in_array((string)($state['status'] ?? ''), ['starting', 'verifying', 'waiting', 'running', 'clearing', 'restoring'], true)
 ) {
 try {
 $state = run_web_worker_step($pdo, $backup_dir, $config, $job_id);
 } catch (Throwable $workerError) {
 $state = read_cli_job_state($backup_dir, $job_id) ?: $state;
 $canRecover = (($state['type'] ?? '') === 'restore')
 && empty($state['recovery_mode'])
 && empty($state['restore_verified']);

 if ($canRecover) {
 $emergencyFile = (string)($state['emergency_file'] ?? '');
 $emergencyJobId = (string)($state['emergency_job_id'] ?? '');
 $emergencyState = null;

 try {
 // Ana iş durumu henüz emergency_file değerini yazamadan hata oluşmuş olabilir.
 // Acil durum işçi süreci tamamlandıysa kendi durum dosyasından dosya bulunup kurtarma yapılabilir.
 if ($emergencyFile === '' && preg_match('/^[a-f0-9]{32}$/', $emergencyJobId)) {
 $emergencyState = read_cli_job_state($backup_dir, $emergencyJobId);
 if (is_array($emergencyState) && is_emergency_state_completed($emergencyState)) {
 $emergencyFile = (string)($emergencyState['file'] ?? '');
 $state['emergency_file'] = $emergencyFile;
 $state['emergency_backup_completed'] = true;
 }
 }

 if ($emergencyFile === '') {
 throw new Exception('Kullanılabilir tamamlanmış Web emergency snapshot bulunamadı.');
 }
 if (!validate_backup_filename($emergencyFile) || !is_emergency_backup_filename($emergencyFile)) {
 throw new Exception('Emergency backup dosya adı geçersiz.');
 }
 $safeEmergency = validate_path_safe($backup_dir . '/' . $emergencyFile, $backup_dir);
 if (!is_file($safeEmergency)) throw new Exception('Emergency backup dosyası bulunamadı.');
 verify_backup_checksum($safeEmergency);

 $state['recovery_mode'] = true;
 $state['recovery_original_error'] = $workerError->getMessage();
 $state['original_restore_file'] = (string)($state['file'] ?? '');
 $state['file'] = $emergencyFile;
 $state['phase'] = 'verify_source';
 $state['status'] = 'running';
 $state['percent'] = 0;
 $state['source_verified'] = false;
 $state['source_gzip_verified'] = false;
 $state['cleanup_verified'] = false;
 $state['processed_bytes'] = 0;
 $state['file_size'] = (int)filesize($safeEmergency);
 $state['verify_offset'] = 0;
 $state['verify_hash_context'] = '';
 $state['restore_verified'] = false;
 $state['message'] = 'Restore başarısız oldu. Web emergency snapshot doğrulanıyor ve eski veritabanı geri yüklenecek.';
 write_cli_job_state($backup_dir, $job_id, $state);
 Logger::warning(sprintf('WEB RESTORE RECOVERY HAZIRLANDI | job_id=%s | emergency_file=%s | error=%s', $job_id, $emergencyFile, $workerError->getMessage()));
 } catch (Throwable $prepError) {
 // Tamamlanmış acil yedek yoksa geri yükleme'un geçici SQL veri akışı'ini de hemen temizle.
 // Böylece preflight/veri akışı aşamasında oluşan disk tüketimi job başarısız olduğunda beklemez.
 if ($emergencyFile === '') {
 cleanup_web_restore_stream_cache($state);
 $state['restore_stream_path'] = '';
 $state['restore_stream_size'] = 0;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = 0;
 }

 // Acil durum anlık görüntüsü tamamlanmadıysa yarım kalan geçici/durum dosyalarını temizle.
 if ($emergencyFile === '' && is_array($emergencyState) && !is_emergency_state_completed($emergencyState)) {
 $tmpFile = (string)($emergencyState['tmp_file'] ?? $emergencyState['backup_tmp_file'] ?? '');
 $targetFile = (string)($emergencyState['target_file'] ?? $emergencyState['backup_target_file'] ?? '');
 $reservationFile = (string)($emergencyState['reservation_file'] ?? $emergencyState['backup_reservation_file'] ?? '');
 foreach ([$tmpFile, $reservationFile] as $artifact) {
 if ($artifact !== '' && is_file($artifact)) @unlink($artifact);
 }
 if ($targetFile !== '' && is_emergency_backup_filename(basename($targetFile)) && is_file($targetFile)) {
 @unlink($targetFile);
 if (is_file($targetFile . '.sha256')) @unlink($targetFile . '.sha256');
 if (is_file($targetFile . '.meta.json')) @unlink($targetFile . '.meta.json');
 }
 if (preg_match('/^[a-f0-9]{32}$/', $emergencyJobId)) {
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json');
 @unlink($backup_dir . '/.cli_job_' . $emergencyJobId . '.json.tmp');
 }
 }
 $state['status'] = 'failed';
 $state['recovered'] = false;
 $state['error'] = $workerError->getMessage();
 $state['recovery_error'] = $prepError->getMessage();
 write_cli_job_state($backup_dir, $job_id, $state);
 mark_restore_maintenance_recovery_required($backup_dir, $job_id, 'WEB restore recovery hazırlanamadı: ' . $prepError->getMessage());
 Logger::error(sprintf('WEB RESTORE RECOVERY HAZIRLANAMADI | job_id=%s | error=%s', $job_id, $prepError->getMessage()));
 }
 } else {
 if (($state['type'] ?? '') === 'restore' && empty($state['emergency_backup_completed'])) {
 cleanup_web_restore_stream_cache($state);
 $state['restore_stream_path'] = '';
 $state['restore_stream_size'] = 0;
 $state['restore_stream_ready'] = false;
 $state['restore_stream_created_at'] = 0;
 }
 $state['status'] = 'failed';
 $state['recovered'] = false;
 $state['error'] = $workerError->getMessage();
 $reservationFile = (string)($state['backup_reservation_file'] ?? $state['reservation_file'] ?? '');
 if ($reservationFile !== '' && is_file($reservationFile)) {
 @unlink($reservationFile);
 }
 write_cli_job_state($backup_dir, $job_id, $state);
 if (($state['type'] ?? '') === 'restore') {
 if (in_array((string)($state['phase'] ?? ''), ['clear_database', 'restore', 'analyze', 'analyze_pending'], true) || !empty($state['emergency_backup_completed'])) {
 mark_restore_maintenance_recovery_required($backup_dir, $job_id, 'WEB restore worker başarısız oldu: ' . $workerError->getMessage());
 } else {
 end_restore_maintenance($backup_dir, $job_id);
 }
 }
 Logger::error(sprintf('WEB WORKER BAŞARISIZ | job_id=%s | type=%s | recovery=N/A | error=%s', $job_id, $state['type'] ?? '-', $workerError->getMessage()));
 }
 }
 }

 json_response(true, 'Job durumu alındı.', $state);
 }

 // PHP Info yalnızca güvenli bölümleri döndürür. INFO_VARIABLES ve INFO_ENVIRONMENT
 // özellikle dışarıda bırakılır; böylece sunucu ortamındaki hassas değişkenlerin
 // yönetim panelinden yanlışlıkla açığa çıkması önlenir.
 if ($action === 'php_info') {
 clear_buffers();
 header('Content-Type: text/html; charset=utf-8');
 header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
 header('Pragma: no-cache');
 header('X-Content-Type-Options: nosniff');
 header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox;");

 ob_start();
 phpinfo(INFO_GENERAL | INFO_CONFIGURATION | INFO_MODULES);
 $phpInfoHtml = (string)ob_get_clean();
 // phpinfo bazı sürümlerde script etiketi üretirse iframe içinde çalıştırılmasını engelle.
 $phpInfoHtml = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', $phpInfoHtml) ?? $phpInfoHtml;
 echo $phpInfoHtml;
 exit;
 }

 if ($action === 'log_stream') {
 // Terminal benzeri gerçek zamanlı log akışı. Tarayıcı 2 saniyelik durumu tekrar sorma
 // yapmaz; sunucu yeni log satırı oluştuğunda canlı veri bağlantısı üzerinden hemen gönderir.
 require_get();
 clear_buffers();
 @set_time_limit(30);
 @ignore_user_abort(true);
 @ini_set('output_buffering', 'off');
 @ini_set('zlib.output_compression', '0');
 if (function_exists('ob_implicit_flush')) {
 @ob_implicit_flush(true);
 }

 header('Content-Type: text/event-stream; charset=utf-8');
 header('Cache-Control: no-cache, no-store, must-revalidate');
 header('Pragma: no-cache');
 header('Expires: 0');
 header('X-Accel-Buffering: no');
 header('Connection: keep-alive');

 // PHP oturumu dosya kilidini uzun canlı veri bağlantısı bağlantısı boyunca tutmasın.
 release_web_session_lock();

 $logPath = $backup_dir . '/system.log';
 $streamStarted = microtime(true);
 $streamMaxSeconds = 25;
 $offset = is_file($logPath) ? (int)filesize($logPath) : 0;
 // Aktif system.log + döndürülmüş logların tamamını ilk bağlantıda gönder.
 $initialLines = read_recent_log_lines($backup_dir, (int)$config['log_rotate_count'], VEDO_LOG_STREAM_INITIAL_LINES);

 // İlk veriyi hemen gönder; proxy/geçici bellek alanı katmanlarını mümkün olduğunca erken uyandır.
 echo "event: init\n";
 echo 'data: ' . json_encode(['lines' => $initialLines], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n\n";
 echo ':' . str_repeat(' ', 2048) . "\n\n";
 @flush();

 while ((microtime(true) - $streamStarted) < $streamMaxSeconds) {
 if (connection_aborted()) break;

 clearstatcache(true, $logPath);
 $currentSize = is_file($logPath) ? (int)filesize($logPath) : 0;

 // Log rotate/temizleme sonrası dosya küçüldüyse yeni dosyanın son 200 satırını tekrar gönder.
 if ($currentSize < $offset) {
 $offset = $currentSize;
 $resetLines = read_recent_log_lines($backup_dir, (int)$config['log_rotate_count'], VEDO_LOG_STREAM_INITIAL_LINES);
 echo "event: replace\n";
 echo 'data: ' . json_encode(['lines' => $resetLines], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n\n";
 @flush();
 } elseif ($currentSize > $offset) {
 $fp = @fopen($logPath, 'rb');
 if ($fp !== false) {
 try {
 if (@fseek($fp, $offset, SEEK_SET) === 0) {
 $buffer = '';
 while (!feof($fp)) {
 $chunk = fread($fp, 65536);
 if ($chunk === false || $chunk === '') break;
 $buffer .= $chunk;
 $parts = preg_split('/\R/', $buffer);
 if ($parts === false) break;
 $buffer = array_pop($parts) ?? '';
 foreach ($parts as $line) {
 if ($line === '') continue;
 echo "event: line\n";
 echo 'data: ' . json_encode(['line' => $line], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n\n";
 }
 }
 }
 } finally {
 fclose($fp);
 }
 $offset = $currentSize;
 @flush();
 }
 }

 // Dosya değişikliğini ~100 ms'de bir kontrol et; fakat ağ trafiğini gereksiz artırmamak için
 // keep-alive canlılık bilgisi'i yalnızca saniyede bir gönder. Yeni log satırı beklemez.
 static $lastHeartbeatAt = 0.0;
 $now = microtime(true);
 if (($now - $lastHeartbeatAt) >= 1.0) {
 echo ": heartbeat\n\n";
 @flush();
 $lastHeartbeatAt = $now;
 }
 usleep(100000);
 }
 exit;
 }

 if ($action === 'get_dashboard_data') {
 $metrics = get_server_metrics($config, $backup_dir);

 // Yedek dosyaları listesi.
 $files = [];
 if (is_dir($backup_dir)) {
 try {
 $iterator = new DirectoryIterator($backup_dir);
 foreach ($iterator as $fileinfo) {
 if ($fileinfo->isFile() && str_ends_with($fileinfo->getFilename(), '.sql.gz') && !is_emergency_backup_filename($fileinfo->getFilename())) {
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
 usort($files, static function (array $a, array $b): int {
 $cmp = strcmp((string)($b['mtime'] ?? ''), (string)($a['mtime'] ?? ''));
 if ($cmp !== 0) return $cmp;
 return strcmp((string)($a['name'] ?? ''), (string)($b['name'] ?? ''));
 });
 } catch (Exception $e) {
 Logger::warning('Yedek listesi okunamadı: ' . $e->getMessage());
 }
 }

 // Log ekranı yalnızca son 200 satıra değil, saklanan tüm aktif/döndürülmüş loglara erişir.
 $logLines = read_recent_log_lines($backup_dir, (int)$config['log_rotate_count'], VEDO_DASHBOARD_LOG_LINES);

 json_response(true, 'Dashboard verileri yüklendi.', [
 'metrics' => $metrics,
 'files' => $files,
 'logs' => $logLines
 ]);
 }

 if ($action === 'client_activity_log') {
 require_post();
 $actionName = trim((string)($_POST['action_name'] ?? ''));
 $details = trim((string)($_POST['details'] ?? ''));

 // Aktivite adı kısa ve hassas veri içermemeli.
 if ($actionName === '' || !preg_match('/^[\p{L}\p{N}_ .:+\-\/()]+$/u', $actionName)) {
 json_response(false, 'Geçersiz aktivite adı.', [], 400);
 }

 $details = vedo_utf8_substr($details, 0, 500);
 // Aktivite ayrıntılarındaki hassas değerleri loglamadan önce maskele.
 $details = preg_replace(
 '/((?:password|passwd|pass|token|secret|csrf|session[_-]?id|authorization|cookie)\s*[:=]\s*)[^|,;\s]+/iu',
 '$1***REDACTED***',
 $details
 ) ?? $details;
 // Kullanıcıdan gelen ayrıntılar log satırını bölerek sahte kayıt üretmemeli.
 $details = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $details) ?? $details;
 $details = preg_replace('/\s{2,}/u', ' ', $details) ?? $details;

 Logger::info('Panel işlemi: ' . $actionName . ($details !== '' ? ' | ' . $details : ''));
 json_response(true, 'Aktivite loglandı.');
 }

if ($action === 'bulk_delete_backups') {
 require_post();

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
 if ($file !== '' && validate_backup_filename($file) && !is_emergency_backup_filename($file)) {
 $files[$file] = true;
 }
 }
 if (!$files) {
 json_response(false, 'Silinecek yedek seçilmedi.', [], 400);
 }

 $deleted = [];
 $failed = [];

 $admissionLock = acquire_job_admission_lock($backup_dir);
 if (!$admissionLock) {
 json_response(false, 'Başka bir veritabanı işlemi başlatılıyor. Toplu yedek silme işlemi başlatılamaz.', [], 409);
 }
 $deleteLock = null;
 try {
 assert_no_active_database_job($backup_dir);
 $deleteLock = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, (int)$config['lock_timeout']);
 if (!$deleteLock) {
 release_job_admission_lock($admissionLock);
 json_response(false, 'Başka bir veritabanı işlemi aktif. Toplu yedek silme işlemi başlatılamaz.', [], 409);
 }

 require_database_operation_lock($deleteLock, $backup_dir);
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
 $safePath . '.meta.json',
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
 } finally {
 if (is_resource($deleteLock)) {
 release_system_lock($deleteLock);
 }
 release_job_admission_lock($admissionLock);
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

 // Manuel veri tabanı temizleme ile geri yükleme öncesi temizleme aynı motoru kullanır.
 // Böylece iki farklı DROP akışının zamanla birbirinden ayrılması önlenir.
 $dbName = (string)$config['db_name'];
 $emptyAdmission = acquire_job_admission_lock($backup_dir);
 if (!$emptyAdmission) {
 json_response(false, 'Başka bir veritabanı işlemi başlatılıyor. Yeni işlem başlatılamaz.', [], 409);
 }
 $emptyLock = null;
 try {
 assert_restore_maintenance_marker_valid($backup_dir);
 assert_no_active_database_job($backup_dir);
 $emptyLock = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, (int)$config['lock_timeout']);
 } catch (Throwable $e) {
 release_job_admission_lock($emptyAdmission);
 json_response(false, $e->getMessage(), [], 409);
 }
 if (!$emptyLock) {
 release_job_admission_lock($emptyAdmission);
 json_response(false, 'Başka bir veritabanı işlemi aktif. Yeni işlem başlatılamaz.', [], 409);
 }

 $errorMessage = null;
 $droppedCount = 0;
 try {
 require_database_operation_lock($emptyLock, $backup_dir);
 update_system_lock_heartbeat($emptyLock);
 $clearReport = clear_database_for_restore($pdo, $dbName);
 $droppedCount = count($clearReport['dropped'] ?? []);
 update_system_lock_heartbeat($emptyLock);
 verify_database_is_empty_for_restore($pdo, $dbName);
 } catch (Throwable $e) {
 $errorMessage = $e->getMessage();
 Logger::error('Veritabanı tamamen temizleme hatası: ' . get_class($e) . ' - ' . $errorMessage);
 } finally {
 release_system_lock($emptyLock);
 release_job_admission_lock($emptyAdmission);
 }

 if ($errorMessage !== null) {
 json_response(false, 'Veritabanı tamamen temizlenemedi: ' . $errorMessage, [
 'database' => $dbName,
 'dropped' => $droppedCount,
 'remaining' => []
 ], 500);
 }

 Logger::warning("VERİTABANI TAMAMEN TEMİZLENDİ: {$dbName}. Silinen nesne sayısı: {$droppedCount}");
 json_response(true, 'Veritabanı tamamen temizlendi. Hiçbir tablo veya veritabanı nesnesi kalmadı.', [
 'database' => $dbName,
 'dropped' => $droppedCount,
 'failed' => [],
 'remaining' => []
 ]);
}

if ($action === 'download_backup') {
 require_post();
 $file = $_POST['file'] ?? '';
 if (!is_string($file) || !validate_backup_filename($file) || is_emergency_backup_filename($file)) {
 json_response(false, 'Yalnızca kullanıcı yedekleri indirilebilir.', [], 400);
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
 $downloadName = str_replace(['\\', '"', "\r", "\n"], '_', basename($safe_path));
 header('Content-Disposition: attachment; filename="' . $downloadName . '"');
 header('Content-Length: ' . filesize($safe_path));
 readfile($safe_path);
 exit;
}

 if ($action === 'delete_backup') {
 require_post();
 Logger::warning('Yedek silme işlemi başlatıldı: ' . (string)($_POST['file'] ?? ''));
 $file = $_POST['file'] ?? '';
 if (!is_string($file) || !validate_backup_filename($file) || is_emergency_backup_filename($file)) {
 json_response(false, 'Yalnızca kullanıcı yedekleri silinebilir.', [], 400);
 }
 $admissionLock = acquire_job_admission_lock($backup_dir);
 if (!$admissionLock) {
 json_response(false, 'Başka bir veritabanı işlemi başlatılıyor. Yedek silme işlemi başlatılamaz.', [], 409);
 }
 $deleteLock = null;
 try {
 assert_no_active_database_job($backup_dir);
 $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
 $deleteLock = acquire_system_lock($backup_dir, VEDO_DATABASE_OPERATION_LOCK, (int)$config['lock_timeout']);
 if (!$deleteLock) {
 release_job_admission_lock($admissionLock);
 json_response(false, 'Başka bir veritabanı işlemi aktif. Yedek silme işlemi başlatılamaz.', [], 409);
 }
 require_database_operation_lock($deleteLock, $backup_dir);
 $deletedOk = false;
 if (is_file($safe_path)) {
 if (!@unlink($safe_path)) {
 throw new Exception('Yedek dosyası silinemedi.');
 }
 $sha_file = $safe_path . '.sha256';
 if (is_file($sha_file)) @unlink($sha_file);
 $meta_file = $safe_path . '.meta.json';
 if (is_file($meta_file)) @unlink($meta_file);
 $deletedOk = true;
 Logger::info("Yedek dosyası silindi: {$file}");
 }
 } finally {
 if (is_resource($deleteLock)) {
 release_system_lock($deleteLock);
 }
 release_job_admission_lock($admissionLock);
 }
 if ($deletedOk) {
 json_response(true, 'Yedek dosyası başarıyla silindi.');
 }
 json_response(false, 'Silinecek dosya bulunamadı.');
 }

 if ($action === 'check_integrity') {
 require_post();
 Logger::info('Yedek bütünlük kontrolü başlatıldı: ' . (string)($_POST['file'] ?? ''));
 $file = $_POST['file'] ?? '';
 if (!is_string($file) || !validate_backup_filename($file) || is_emergency_backup_filename($file)) {
 json_response(false, 'Yalnızca kullanıcı yedekleri doğrulanabilir.', [], 400);
 }
 $safe_path = validate_path_safe($backup_dir . '/' . $file, $backup_dir);
 if (!is_file($safe_path)) json_response(false, 'Yedek dosyası bulunamadı.', [], 404);

 $cli = detect_cli_worker_capability();
 if ($cli['available']) {
 $job_id = bin2hex(random_bytes(16));
 if (!spawn_cli_job(__FILE__, $backup_dir, $config['cron_token'], 'integrity', $job_id, $file)) {
 json_response(false, 'Arka plan bütünlük kontrolü başlatılamadı.', [], 500);
 }
 json_response(true, 'Bütünlük kontrolü arka planda başlatıldı.', ['async'=>true, 'job_id'=>$job_id, 'file'=>$file]);
 }

 // CLI yoksa küçük dosyada normal yol kullanılır; büyük dosyada WEB sınırı kontrol edilir.
 if ((int)filesize($safe_path) > 128 * 1024 * 1024) {
 json_response(false, 'Bu sunucuda CLI Worker bulunmadığı için 128 MB üzerindeki yedeklerin bütünlük kontrolü WEB isteği içinde güvenli şekilde çalıştırılamaz.', [], 503);
 }
 $hash = verify_backup_checksum($safe_path);
 $validation = validate_backup_restore_compatibility($safe_path, false, (string)$config['db_name']);
 json_response(true, 'Bütünlük + test restore doğrulaması BAŞARILI.', ['hash' => $hash, 'restore_validation' => $validation]);
 }

 if ($action === 'clear_logs') {
 require_post();
 // Kullanıcı 'logları temizle' dediğinde yalnızca aktif system.log değil,
 // döndürülmüş system.log.1 ... system.log.5 dosyaları da temizlenir.
 // Aksi halde geniş log ekranı eski kayıtları göstermeye devam eder.
 $logFiles = [$backup_dir . '/system.log'];
 for ($i = 1; $i <= 5; $i++) $logFiles[] = $backup_dir . '/system.log.' . $i;

 $failed = [];
 foreach ($logFiles as $logPath) {
 if (!is_file($logPath)) continue;
 if (!safe_file_put_contents($logPath, '', LOCK_EX)) $failed[] = basename($logPath);
 }

 if ($failed) {
 Logger::error('Log temizleme başarısız | dosyalar=' . implode(', ', $failed));
 json_response(false, 'Bazı log dosyaları temizlenemedi: ' . implode(', ', $failed), [], 500);
 }

 // Temizlikten sonra kullanıcıya işlemin tamamlandığını gösterecek tek yeni kayıt bırak.
 Logger::success('TÜM SİSTEM LOGLARI TEMİZLENDİ | system.log ve döndürülmüş kayıtlar temizlendi.');
 json_response(true, 'Tüm sistem logları başarıyla temizlendi.');
 }

 // Varsayılan seçim CLI'dir; WEB seçilirse Web işçi süreci zorunlu olarak kullanılır.
 if ($action === 'restore_chunk') {
 require_post();
 $file = trim((string)($_POST['file'] ?? ''));
 if (!validate_backup_filename($file) || is_emergency_backup_filename($file)) {
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
 if (spawn_cli_job(__FILE__, $backup_dir, $config['cron_token'], 'restore', $job_id, $file)) {
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
 try {
 $state = initialize_web_restore_job($pdo, $backup_dir, $config, $job_id, $file);
 } catch (Throwable $e) {
 json_response(false, $e->getMessage(), ['engine' => 'web', 'job_id' => $job_id], 409);
 }
 json_response(true, 'Web Worker restore başlatıldı.', [
 'status' => $state['status'],
 'percent' => 0,
 'job_id' => $job_id,
 'file' => $file,
 'engine' => 'web'
 ]);
 }

 } catch (Throwable $e) {
 Logger::error("API İşlem Hatası ({$action}): " . get_class($e) . ' - ' . $e->getMessage());
 json_response(false, 'API işlemi başarısız oldu. Ayrıntı için sistem loglarını kontrol edin.', [], 500);
 }
}

// =============================================================================
// PHP - YÖNETİM PANELİNE GEÇİŞ

/*
PANELDE PHP + HTML + CSS + JAVASCRIPT
Giriş başarılı olduktan sonra aynı PHP dosyası yönetim panelini üretir.

Burada dört teknoloji birlikte çalışır:
- PHP: Sunucu tarafında veriyi ve işlemleri yönetir.
- HTML: Ekranın iskeletini oluşturur.
- CSS: Görünümü düzenler.
- JavaScript: Kullanıcı hareketlerini yönetir ve PHP API'sine
 istek gönderir.

Bu nedenle dosyayı okurken "hangi kod nerede çalışıyor?" sorusunu
sormak çok önemlidir.
*/

// Kullanıcı giriş yaptıktan sonra panelin HTML/CSS/JavaScript arayüzü hazırlanır.
// CLI komutu da burada oluşturulur; cron_token değeri sabit kalır.
// =============================================================================

$cli_cron_command = 'php ' . escapeshellarg(__FILE__) . ' ' . $config['cron_token'];
clear_buffers();
?>
<!--
============================================================
HTML / KULLANICI ARAYÜZÜ
Bu bölüm tarayıcıda görünen sayfanın iskeletini oluşturur.
HTML; başlıklar, butonlar, tablolar, formlar ve diğer arayüz
elemanlarının hangi sırada bulunacağını belirler.
PHP burada sunucu tarafında hazırladığı verileri HTML içine
yerleştirebilir.

Öğrenci için düşünme sırası:
1) PHP sunucuda ne hazırlıyor?
2) HTML kullanıcıya ne gösteriyor?
3) CSS bunun görünümünü nasıl değiştiriyor?
4) JavaScript kullanıcı hareketine nasıl cevap veriyor?
============================================================
-->
<!DOCTYPE html>
<html lang="tr">
<head>

 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>VEDO MySQL Backup & Enterprise Panel</title>
 <style nonce="<?= $nonce ?>">
 /* ANA PANEL CSS
 Panelin renklerini, kartlarını, tablolarını, butonlarını, modallarını ve
 mobil görünümünü düzenleyen tüm görsel kurallar burada bulunur.
 CSS veri tabanı işlemi yapmaz; yalnızca arayüzün nasıl görüneceğini belirler. */
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

 .btn-sm { padding: 4px 8px; }
 .text-right { text-align: right; }
 .text-center { text-align: center; }
 .muted { color: var(--text-secondary); }
 .empty-state { padding: 12px; color: var(--text-secondary); }
 .empty-state-lg { padding: 20px; color: var(--text-secondary); }
 .db-controls-row { display:flex; gap:8px; justify-content:flex-end; align-items:center; margin-top:10px; }
 .db-page-info { padding:8px; color:var(--text-secondary); }
 .log-actions { display:flex; gap:6px; align-items:center; }
 .log-header-tools {
 display:flex;
 align-items:center;
 justify-content:flex-end;
 gap:8px;
 min-width:0;
 }
 .log-header-tools #logSearch {
 width:260px;
 max-width:32vw;
 min-width:150px;
 box-sizing:border-box;
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
 width: 100%;
 min-width: 0;
 max-width: 100%;
 }

 /* Live Progress Panel */
 #live-progress-panel {
 border-left: 4px solid var(--accent-blue);
 display: none;
 }

 .bg-live-indicator {
 display: inline-block;
 margin-left: 8px;
 opacity: .35;
 transform: scale(.8);
 transition: opacity .2s ease, transform .2s ease;
 }
 .bg-live-indicator.active {
 opacity: 1;
 transform: scale(1);
 animation: vedoProgressPulse 1s ease-in-out infinite;
 }
 .bg-live-indicator.success { opacity: 1; animation: none; }
 .bg-live-indicator.error { opacity: 1; animation: none; }
 @keyframes vedoProgressPulse {
 0%, 100% { opacity: .35; transform: scale(.75); }
 50% { opacity: 1; transform: scale(1.15); }
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

 /*
 * MEVCUT YEDEKLER: Bu panel diğer panel kutularıyla birebir aynı genişlikte kalır.
 * İç tablo hiçbir durumda paneli yatayda büyütemez; genişlik tamamen panelden miras alınır.
 * Uzun dosya adları hücre içinde kırılır; işlem düğmeleri tek satırda korunur.
 */
 .panel-box.backups-panel {
 display: block;
 width: 100% !important;
 max-width: 100% !important;
 min-width: 0 !important;
 box-sizing: border-box !important;
 overflow: hidden;
 }
 .backups-panel .bulk-backup-toolbar {
 width: 100%;
 max-width: 100%;
 min-width: 0;
 box-sizing: border-box;
 flex-wrap: wrap;
 }
 .backups-table-wrap {
 display: block;
 width: 100% !important;
 max-width: 100% !important;
 min-width: 0 !important;
 box-sizing: border-box;
 overflow-x: auto;
 overflow-y: hidden;
 }
 #backupsTable {
 display: table;
 width: 100% !important;
 max-width: 100% !important;
 min-width: 0 !important;
 box-sizing: border-box;
 table-layout: fixed !important;
 }
 #backupsTable th, #backupsTable td {
 min-width: 0 !important;
 max-width: 0;
 overflow-wrap: anywhere;
 word-break: break-word;
 }
 /*
 * Tablo genişlikleri ekrandaki gerçek kullanım için dengelenir.
 * Dosya adı en geniş alanı alır; Boyut/Tarih/SHA256 biraz sola çekilir.
 * İşlemler sütunu dört butonu tek satırda tutacak kadar geniş bırakılır.
 */
 #backupsTable th:nth-child(1), #backupsTable td:nth-child(1) { width: 43%; text-align: left; }
 #backupsTable th:nth-child(2), #backupsTable td:nth-child(2) { width: 8%; text-align: right; }
 #backupsTable th:nth-child(3), #backupsTable td:nth-child(3) { width: 12%; text-align: right; }
 #backupsTable th:nth-child(4), #backupsTable td:nth-child(4) { width: 14%; text-align: right; }
 #backupsTable th:nth-child(5), #backupsTable td:nth-child(5) { width: 23%; text-align: right; }
 #backupsTable th:nth-child(n+2), #backupsTable td:nth-child(n+2) {
 text-align: right !important;
 }
 #backupsTable td:nth-child(4) .badge, #backupsTable td:nth-child(4) .status-badge {
 display: inline-block;
 white-space: nowrap;
 }
 #backupsTable .backup-file-cell {
 min-width: 0 !important;
 max-width: 0;
 }
 #backupsTable td:last-child, #backupsTable th:last-child {
 white-space: nowrap !important;
 }
 #backupsTable td:last-child {
 overflow: visible;
 }
 #backupsTable td:last-child .btn {
 display: inline-flex;
 align-items: center;
 justify-content: center;
 white-space: nowrap;
 margin: 0 0 0 4px;
 padding: 6px 8px;
 }

 /* Tables */
 table {
 width: 100%;
 max-width: 100%;
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
 .log-header-tools select {
 background: var(--surface-2);
 border: 1px solid var(--line);
 color: var(--text);
 padding: 6px 10px;
 border-radius: 4px;
 min-width: 132px;
 box-sizing: border-box;
 }

 @media (max-width: 760px) {
 .log-section-title { align-items:flex-start; gap:10px; flex-wrap:wrap; }
 .log-header-tools { width:100%; justify-content:flex-end; flex-wrap:wrap; }
 .log-header-tools #logSearch { width:100%; max-width:none; min-width:0; flex:1 1 220px; }
 .log-header-tools select { flex:0 1 150px; }
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

 .log-line-SUCCESS { color: #a5d6a7; }
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
 .db-toolbar { display:flex; flex-wrap:wrap; gap:5px; align-items:center; margin-bottom:10px; }
 .db-toolbar .btn { padding:6px 10px; font-size:12px; white-space:nowrap; }
 .db-toolbar select,.db-toolbar input { background:var(--surface-2); border:1px solid var(--line); color:var(--text); padding:6px 8px; border-radius:4px; font-size:12px; }
 .db-toolbar #dbSqlImportMode { min-width:0; }
 .db-section-tools { display:flex; align-items:center; justify-content:flex-end; flex-wrap:wrap; gap:5px; min-width:0; }
 .db-section-tools .btn { padding:5px 8px; font-size:11px; white-space:nowrap; }
 .db-section-tools select { padding:5px 7px; font-size:11px; min-width:0; max-width:150px; }
 .db-section-tools .badge { white-space:nowrap; }
 @media (max-width:760px) {
 .db-section-tools { width:100%; justify-content:flex-start; margin-top:6px; }
 .section-title { flex-wrap:wrap; }
 }
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
 LOG EKRANI — TERMİNAL GÖRÜNÜMÜ
 Koyu temada genel metin açık gri; bilgi/mutlu/uyarı/hata
 kayıtları birbirinden net biçimde ayrılır.
 ========================================================== */
.log-box,
#logBoxContainer{
 color:#d7dee8 !important;
 background:#050505 !important;
 border:1px solid #242424 !important;
 font-size:15px !important;
 line-height:1.65 !important;
 font-weight:500 !important;
 letter-spacing:.01em !important;
 text-shadow:none !important;
 user-select:text !important;
 -webkit-user-select:text !important;
 cursor:text !important;
}
.log-box *,
#logBoxContainer * {
 user-select:text !important;
 -webkit-user-select:text !important;
}
.log-box .log-line-SUCCESS,#logBoxContainer .log-line-SUCCESS{ color:#67e8a5 !important; }
.log-box .log-line-INFO,#logBoxContainer .log-line-INFO{ color:#5cc8ff !important; }
.log-box .log-line-WARNING,#logBoxContainer .log-line-WARNING{ color:#ffd166 !important; }
.log-box .log-line-ERROR,#logBoxContainer .log-line-ERROR{ color:#ff6b6b !important; }
.log-controls input,.log-controls select{
 font-family: var(--vedo-ui-font) !important;
}

/*
 * AÇIK TEMA — LOG EKRANI
 * Açık temada log kutuları tamamen beyaz kullanılır.
 * Seviye renkleri okunabilirlik için ayrı tutulur: bilgi=mavi, başarı=yeşil,
 * uyarı=amber, hata=kırmızı. Koyu temanın terminal görünümü değişmez.
 */
html.theme-light .log-box,
html.theme-light #logBoxContainer,
html.theme-light .log-modal-body .log-box {
 background: #ffffff !important;
 color: #17212b !important;
 border-color: #d7e0e8 !important;
 text-shadow: none !important;
}
html.theme-light .log-box .log-line-SUCCESS,
html.theme-light #logBoxContainer .log-line-SUCCESS {
 color: #168a4d !important;
}
html.theme-light .log-box .log-line-INFO,
html.theme-light #logBoxContainer .log-line-INFO {
 color: #155eef !important;
}
html.theme-light .log-box .log-line-WARNING,
html.theme-light #logBoxContainer .log-line-WARNING {
 color: #a15c00 !important;
}
html.theme-light .log-box .log-line-ERROR,
html.theme-light #logBoxContainer .log-line-ERROR {
 color: #b42318 !important;
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
 .php-version-link {
 color: inherit;
 text-decoration: underline;
 text-decoration-thickness: 1px;
 text-underline-offset: 3px;
 cursor: pointer;
 border-radius: 4px;
 }
 .php-version-link:hover { opacity: .82; }
 .php-version-link:focus-visible {
 outline: 2px solid var(--primary);
 outline-offset: 3px;
 }
 .phpinfo-overlay {
 position: fixed;
 inset: 0;
 z-index: 1400;
 display: none;
 align-items: center;
 justify-content: center;
 padding: 20px;
 background: rgba(0,0,0,.78);
 backdrop-filter: blur(5px);
 }
 .phpinfo-overlay.open { display: flex; }
 .phpinfo-modal {
 width: min(1280px, 97vw);
 height: min(900px, 94vh);
 display: flex;
 flex-direction: column;
 background: var(--panel);
 border: 1px solid var(--panel-border);
 border-radius: 14px;
 box-shadow: 0 24px 80px rgba(0,0,0,.5);
 overflow: hidden;
 }
 .phpinfo-modal-head {
 display:flex;
 align-items:center;
 justify-content:space-between;
 gap:16px;
 padding:16px 20px;
 border-bottom:1px solid var(--line);
 background:var(--surface-2);
 flex: 0 0 auto;
 }
 .phpinfo-modal-body {
 position: relative;
 flex: 1 1 auto;
 min-height: 0;
 background: #fff;
 }
 .phpinfo-frame {
 display:block;
 width:100%;
 height:100%;
 min-height:0;
 border:0;
 background:#fff;
 }
 .phpinfo-loading {
 position:absolute;
 inset:0;
 z-index:1;
 display:flex;
 align-items:center;
 justify-content:center;
 background:#fff;
 color:#333;
 font:14px Tahoma, Arial, sans-serif;
 }
 .phpinfo-loading.hidden { display:none; }

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
 <div class="worker-mode-control" title="Uzun işlemler bağımsız CLI arka plan worker ile yürütülür.">
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
 <div class="card-value" style="margin-top:5px;"><a href="#php-info" class="php-version-link" id="m-php-ver" title="PHP bilgilerini aç">-</a></div>
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

 <!-- PHP INFO POPUP: PHP sürüm bağlantısına tıklanınca panel içinde açılır. -->
 <div class="phpinfo-overlay" id="phpInfoOverlay" aria-hidden="true">
 <div class="phpinfo-modal" role="dialog" aria-modal="true" aria-labelledby="phpInfoModalTitle">
 <div class="phpinfo-modal-head">
 <div>
 <div class="server-info-modal-title" id="phpInfoModalTitle">PHP Info</div>
 <div class="server-info-modal-subtitle">PHP çalışma ortamı, yapılandırma ve yüklü uzantılar</div>
 </div>
 <button class="server-info-close" id="btnClosePhpInfo" type="button" aria-label="PHP Info penceresini kapat">&times;</button>
 </div>
 <div class="phpinfo-modal-body">
 <div class="phpinfo-loading" id="phpInfoLoading">PHP bilgileri yükleniyor...</div>
 <iframe class="phpinfo-frame" id="phpInfoFrame" title="PHP Info" sandbox></iframe>
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
 <div class="section-title">
 <span>Veritabanı Gezgini</span>
 <div class="db-section-tools">
 <span class="badge badge-success" id="dbNameBadge">-</span>
 <select id="dbSqlImportMode" class="btn btn-secondary" title="SQL import çalışma şekli" aria-label="SQL import çalışma şekli">
 <option value="safe">Güvenli Import</option>
 <option value="soft">Yumuşak Import</option>
 </select>
 <button class="btn btn-green" id="dbSqlImportBtn" type="button">SQL İçeri Aktar</button>
 <input type="file" id="dbSqlImportFile" accept=".sql,text/plain,application/sql" style="display:none">
 <button class="btn btn-red" id="dbEmptyDatabaseBtn" type="button">Veritabanını Tamamen Temizle</button>
 </div>
 </div>
 <div class="db-explorer">
 <aside class="db-sidebar" id="dbTableList"><div class="empty-state">Tablolar yükleniyor...</div></aside>
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
 </div>
 <div id="dbTableMeta" style="color:var(--text-secondary);margin-bottom:10px;">-</div>
 <div class="db-data-wrap" id="dbDataWrap"><div class="empty-state-lg">Tablo seçildiğinde veriler burada görünecek.</div></div>
 <div class="db-controls-row">
 <button class="btn btn-secondary" id="dbPrevBtn" type="button">‹ Önceki</button>
 <span id="dbPageInfo" class="db-page-info">0</span>
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
 <span id="bg-progress-title">Canlı Yedekleme İlerlemesi</span>
 <span class="badge badge-warning" id="bg-status-badge">ÇALIŞIYOR</span>
 </div>
 <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
 <span id="bg-status-text">Yedekleme hazırlanıyor...</span>
 <span id="bg-live-indicator" class="bg-live-indicator" aria-hidden="true">●</span>
 <span id="bg-percent-text" >0%</span>
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
 <span>TABLO SIRASI</span>
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

 <!-- SİSTEM LOGLARI -->
 <div class="panel-box">
 <div class="section-title log-section-title">
 <span>Sistem Logları</span>
 <div class="log-header-tools">
 <input type="text" id="logSearch" placeholder="Loglarda ara..." aria-label="Loglarda ara">
 <select id="logLevelFilter" aria-label="Log seviyesi">
 <option value="ALL">Tüm Seviyeler</option>
 <option value="INFO">INFO</option>
 <option value="WARNING">WARNING</option>
 <option value="ERROR">ERROR</option>
 </select>
 <div class="log-actions">
 <button class="btn btn-secondary btn-sm" id="btnOpenLogs" type="button">Logları Büyüt</button>
 <button class="btn btn-secondary btn-sm" id="btnClearLogs" type="button">Logları Temizle</button>
 </div>
 </div>
 </div>
 <div class="log-box" id="logBoxContainer">Log yükleniyor...</div>
 </div>
 <!-- MEVCUT YEDEKLER TABLOSU -->
 <div class="panel-box backups-panel">
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
 <div class="backups-table-wrap">
 <table id="backupsTable">
 <thead>
 <tr>
 <th>Dosya Adı</th>
 <th>Boyut</th>
 <th>Tarih</th>
 <th>Bütünlük (SHA256)</th>
 <th class="text-right">İşlemler</th>
 </tr>
 </thead>
 <tbody id="backups-list">
 <tr><td colspan="5" class="text-center muted">Yükleniyor...</td></tr>
 </tbody>
 </table>
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

</div>

<script nonce="<?= $nonce ?>">
 // =============================================================================
 // JAVASCRIPT - ANA PANELİN ETKİLEŞİMLERİ
 // JavaScript tarayıcı tarafında çalışır. Buton tıklamalarını, API isteklerini,
 // ilerleme çubuğunu, canlı logları, tablo işlemlerini ve tema değişimini yönetir.
 // PHP sunucu tarafında; JavaScript ise kullanıcının tarayıcısında çalışır.
 // =============================================================================
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
 // Canlı metrik yenilemesi kısa ama gereksiz derecede agresif olmayan bir aralıkla yapılır.
 const LIVE_METRICS_INTERVAL_MS = <?= VEDO_LIVE_METRICS_INTERVAL_MS ?>;
 const MAX_CLIENT_LOG_LINES = <?= VEDO_CLIENT_LOG_MAX_LINES ?>;
 let rawLogLines = [];

 // JAVASCRIPT FONKSİYONU: Log satırlarını tarayıcı tarafında standart bir biçime çevirir ve gereksiz satırları ayıklar.
function normalizeClientLogLines(lines)
 {
 const normalized = Array.isArray(lines) ? lines.map(String) : [];
 return normalized.length > MAX_CLIENT_LOG_LINES
 ? normalized.slice(-MAX_CLIENT_LOG_LINES)
 : normalized;
 }
 let progressInterval = null;
 let activeProgressEngine = '';
 let cliJobStartedThisPage = false;
 let dbTables = [];
 let dbSelectedTable = '';
 let dbOffset = 0;
 // Veritabanı gezgini ana sayfayı ağırlaştırmamak için yalnızca ilk açılışta yüklenir.
 let dbExplorerLoaded = false;
 const DB_PAGE_SIZE = 50;

 // Toast Bildirimi
 // JAVASCRIPT FONKSİYONU: Kullanıcıya kısa süreli başarı, bilgi veya hata mesajı gösterir.
function showToast(message, isError = false)
 {
 const container = document.getElementById('toast-container');
 const toast = document.createElement('div');
 toast.className = `toast ${isError ? 'toast-error' : 'toast-success'}`;
 toast.textContent = message;
 container.appendChild(toast);
 setTimeout(() => {
 toast.style.opacity = '0';
 setTimeout(() => toast.remove(), 300);
 }, 4000);
 }

 // Modern modal onay katmanı: browser confirm() yerine kullanılır.
 let vedoConfirmResolver = null;
 // JAVASCRIPT FONKSİYONU: Silme veya veri kaybı oluşturabilecek işlemler için özel onay penceresi açar.
function showConfirm(message, title = 'İşlemi onayla', confirmText = 'Devam Et')
 {
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

 // JAVASCRIPT FONKSİYONU: Açık olan özel onay penceresini kapatır ve seçilen sonucu döndürür.
function closeConfirm(result = false)
 {
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

 // XSS için HTML kaçış yardımcı fonksiyonu
 // JAVASCRIPT FONKSİYONU: Sunucudan gelen metni HTML olarak yorumlatmadan güvenli biçimde ekrana koyar.
function escapeHtml(str)
 {
 return String(str)
 .replace(/&/g, '&amp;')
 .replace(/</g, '&lt;')
 .replace(/>/g, '&gt;')
 .replace(/"/g, '&quot;')
 .replace(/'/g, '&#039;');
 }

 // Tüm AJAX/API çağrılarını tek noktadan yönetir.
 // JAVASCRIPT FONKSİYONU: PHP tarafındaki API action değerine istek gönderir; POST kullanır ve CSRF bilgisini taşır.
/*
 * ASENKRON JAVASCRIPT
 * "async" kullanılan fonksiyonlarda tarayıcı, sunucudan cevap
 * beklerken arayüzün diğer işlemlerini yönetebilir.
 * "await" ise belirli bir işlemin sonucunu beklemeyi kolaylaştırır.
 * Bu yapı özellikle fetch() ile PHP API çağrılarında kullanılır.
 */
async function apiRequest(action, data = {}, usePost = true) {
 const isPost = usePost;
 const body = isPost ? new URLSearchParams() : null;
 if (body) {
 body.append('csrf_token', CSRF_TOKEN);
 for (const [key, value] of Object.entries(data)) {
 body.append(key, value);
 }
 }

 const url = `?action=${encodeURIComponent(action)}`;

 const controller = new AbortController();
 const timeoutId = setTimeout(() => controller.abort(), 30000);

 let response;
 try {
 response = await fetch(url, {
 method: isPost ? 'POST' : 'GET',
 credentials: 'same-origin',
 cache: 'no-store',
 headers: {
 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
 'X-CSRF-TOKEN': CSRF_TOKEN,
 'Accept': 'application/json'
 },
 body: isPost ? body.toString() : undefined,
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

 // Dashboard: sunucu, veritabanı, yedek ve log bilgilerini tek istekte yeniler.
 let dashboardRequest = null;
 // JAVASCRIPT FONKSİYONU: Dashboard verilerini API üzerinden alır ve paneldeki bilgileri yeniler.
async function loadDashboard() {
 if (dashboardRequest) return dashboardRequest;
 dashboardRequest = (async () => {
 try {
 const res = await apiRequest('get_dashboard_data', {}, false);
 const m = res.data.metrics;
 const files = res.data.files;
 if (!logEventSource) rawLogLines = normalizeClientLogLines(res.data.logs || []);
 latestServerMetrics = m;
 const serverInfoOverlay = document.getElementById('serverInfoOverlay');
 if (serverInfoOverlay && serverInfoOverlay.classList.contains('open')) {
 renderServerInfo(m);
 }

 // Metrik bilgilerini güncelle
 document.getElementById('m-cpu-pct').textContent = m.cpu.percent + '%';
 document.getElementById('m-cpu-load').textContent = m.cpu.load_1min;
 document.getElementById('m-cpu-cores').textContent = m.cpu.cores;
 document.getElementById('m-cpu-bar').style.width = m.cpu.percent + '%';

 document.getElementById('m-ram-pct').textContent = m.ram.percent + '%';
 document.getElementById('m-ram-used').textContent = formatBytes(m.ram.used);
 document.getElementById('m-ram-total').textContent = formatBytes(m.ram.total);
 document.getElementById('m-ram-bar').style.width = m.ram.percent + '%';

 document.getElementById('m-disk-pct').textContent = m.disk.percent + '%';
 document.getElementById('m-disk-free').textContent = formatBytes(m.disk.free);
 document.getElementById('m-disk-total').textContent = formatBytes(m.disk.total);
 document.getElementById('m-disk-bar').style.width = m.disk.percent + '%';

 document.getElementById('m-mysql-ver').textContent = m.mysql_version;
 document.getElementById('m-uptime').textContent = m.uptime;

 document.getElementById('m-php-ver').textContent = m.php_version;
 document.getElementById('m-php-mem').textContent = m.php_env.memory_limit;

 document.getElementById('m-db-size').textContent = m.database.formatted_size;
 document.getElementById('m-db-tables').textContent = m.database.table_count.toLocaleString('tr-TR');
 document.getElementById('m-db-rows').textContent = m.database.total_rows.toLocaleString('tr-TR');
 // Yedek dosyalarını oluştur ve ekrana getir
 renderBackupTable(files);

 // Logları oluştur ve ekrana getir
 filterLogs();

 } catch (err) {
 showToast('Dashboard yüklenirken hata: ' + err.message, true);
 } finally {
 dashboardRequest = null;
 }
 })();
 return dashboardRequest;
 }
 // JAVASCRIPT FONKSİYONU: Tarayıcıda daha önce seçilmiş yedek dosyalarının listesini okur.
function getPersistedBackupSelection()
 {
 try {
 const raw = sessionStorage.getItem('vedo_backup_selection');
 const arr = raw ? JSON.parse(raw) : [];
 return new Set(Array.isArray(arr) ? arr : []);
 } catch (e) {
 return new Set();
 }
 }
 // JAVASCRIPT FONKSİYONU: Kullanıcının yedek seçimlerini tarayıcının localStorage alanına kaydeder.
function persistBackupSelection()
 {
 try {
 sessionStorage.setItem('vedo_backup_selection', JSON.stringify(getSelectedBackupFiles()));
 } catch (e) {}
 }
 // JAVASCRIPT FONKSİYONU: Arayüzde seçili olan yedek dosyalarının adlarını toplar.
function getSelectedBackupFiles()
 {
 return Array.from(document.querySelectorAll('#backups-list .backup-select:checked'))
 .map(el => el.value || el.closest('tr')?.dataset.file || '')
 .filter(Boolean);
 }
 // JAVASCRIPT FONKSİYONU: Yedek seçim kutularının durumunu ve toplu işlem butonlarını günceller.
function updateBackupSelectionUI()
 {
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
 // JAVASCRIPT FONKSİYONU: Sayfa yeniden açıldığında daha önce seçilmiş yedekleri tekrar işaretler.
function restoreBackupSelection()
 {
 const saved = getPersistedBackupSelection();
 document.querySelectorAll('#backups-list .backup-select').forEach(cb => {
 cb.checked = saved.has(cb.value || cb.closest('tr')?.dataset.file || '');
 });
 updateBackupSelectionUI();
 }

 // JAVASCRIPT FONKSİYONU: Birden fazla seçilmiş yedeği tek işlemle silmek için API çağrısı yapar.
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
 // JAVASCRIPT FONKSİYONU: Tüm veri tabanını temizleme gibi çok tehlikeli işlemi kullanıcı onayıyla başlatır.
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
 if (dbSelectedLabel) dbSelectedLabel.textContent = '-';
 if (dbDataWrap) dbDataWrap.innerHTML = '<div class="empty-state-lg">Veritabanında tablo bulunmuyor.</div>';
 if (dbPageInfo) dbPageInfo.textContent = '0-0';

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
 // JAVASCRIPT FONKSİYONU: Sunucudan gelen yedek listesini HTML tablo satırlarına dönüştürür.
function renderBackupTable(files)
 {
 const tbody = document.getElementById('backups-list');
 if (!files || files.length === 0) {
 tbody.innerHTML = '<tr><td colspan="5" class="text-center muted">Henüz oluşturulmuş yedek bulunmuyor.</td></tr>';
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
 <td class="text-right">
 <button class="btn btn-blue btn-sm" data-action="download" data-file="${escapeHtml(f.name)}">İndir</button>
 <button class="btn btn-secondary btn-sm" data-action="verify" data-file="${escapeHtml(f.name)}">Doğrula</button>
 <button class="btn btn-green btn-sm" data-action="restore" data-file="${escapeHtml(f.name)}">Restore</button>
 <button class="btn btn-red btn-sm" data-action="delete" data-file="${escapeHtml(f.name)}">Sil</button>
 </td>
 </tr>
 `).join('');
 restoreBackupSelection();
 }
 // Byte değerlerini hem dashboard hem canlı metrikler için tek yardımcıyla biçimlendirir.
 function formatBytes(bytes)
 {
 const n = Number(bytes);
 if (!Number.isFinite(n) || n <= 0) return '0 B';
 const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
 const i = Math.min(sizes.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
 return parseFloat((n / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
 }

 // Veritabanı gezgini yalnızca modal açıldığında yüklenir; ana dashboard açılışını hızlandırır.
 // JAVASCRIPT FONKSİYONU: Veri tabanındaki tabloları API ile alır ve tablo seçme alanını doldurur.
async function loadDatabaseTables(selectFirst = true) {
 try {
 const res = await apiRequest('db_tables', {}, false);
 dbTables = res.data.tables || [];
 dbExplorerLoaded = true;
 document.getElementById('dbNameBadge').textContent = res.data.database || '-';
 const list = document.getElementById('dbTableList');
 if (!dbTables.length) { list.innerHTML = '<div class="empty-state">Tablo bulunamadı.</div>'; return; }
 list.innerHTML = dbTables.map(t => `<div class="db-table-item ${t.TABLE_NAME===dbSelectedTable?'active':''}" data-db-table="${escapeHtml(t.TABLE_NAME)}"><span>${escapeHtml(t.TABLE_NAME)}</span><small>${Number(t.TABLE_ROWS||0).toLocaleString()}</small></div>`).join('');
 if (selectFirst && !dbSelectedTable) dbSelectedTable = dbTables[0].TABLE_NAME;
 if (dbSelectedTable) await selectDatabaseTable(dbSelectedTable);
 } catch (e) { showToast('Tablolar yüklenemedi: ' + e.message, true); }
 }

 // JAVASCRIPT FONKSİYONU: Seçilen tabloyu aktif tablo olarak belirler ve tablo bilgilerini yüklemeye hazırlar.
async function selectDatabaseTable(table) {
 dbSelectedTable = table; dbOffset = 0;
 document.getElementById('dbSelectedTable').textContent = table;
 document.querySelectorAll('[data-db-table]').forEach(el => el.classList.toggle('active', el.dataset.dbTable === table));
 await loadDatabaseTableData();
 }

 // JAVASCRIPT FONKSİYONU: Seçili tablonun verilerini API üzerinden alıp ekrana getirir.
async function loadDatabaseTableData() {
 if (!dbSelectedTable) return;
 try {
 const res = await apiRequest('db_table_data', {table: dbSelectedTable, limit: DB_PAGE_SIZE, offset: dbOffset});
 const rows = res.data.rows || [];
 const meta = dbTables.find(t => t.TABLE_NAME === dbSelectedTable);
 document.getElementById('dbTableMeta').textContent = meta ? `${meta.TABLE_TYPE} • ${meta.ENGINE || 'N/A'} • ${Number(meta.TABLE_ROWS||0).toLocaleString()} satır • ${meta.FORMATTED_SIZE}` : '';
 const wrap = document.getElementById('dbDataWrap');
 if (!rows.length) { wrap.innerHTML = '<div class="empty-state-lg">Bu sayfada veri yok.</div>'; }
 else {
 const cols = Object.keys(rows[0]);
 wrap.innerHTML = `<table><thead><tr>${cols.map(c=>`<th>${escapeHtml(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${cols.map(c=>`<td title="${escapeHtml(r[c] ?? '')}">${escapeHtml(r[c] ?? 'NULL')}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
 }
 document.getElementById('dbPageInfo').textContent = `${dbOffset + 1}-${dbOffset + rows.length}`;
 document.getElementById('dbPrevBtn').disabled = dbOffset === 0;
 document.getElementById('dbNextBtn').disabled = rows.length < DB_PAGE_SIZE;
 } catch (e) { showToast('Tablo verisi yüklenemedi: ' + e.message, true); }
 }

 // JAVASCRIPT FONKSİYONU: Seçili tablonun kolon ve yapı bilgisini API üzerinden alıp gösterir.
async function loadDatabaseStructure() {
 if (!dbSelectedTable) return showToast('Önce tablo seç.', true);
 try {
 const res = await apiRequest('db_table_structure', {table: dbSelectedTable});
 const cols = res.data.columns || [];
 document.getElementById('dbDataWrap').innerHTML = `<table><thead><tr><th>Kolon</th><th>Tip</th><th>Null</th><th>Key</th><th>Default</th><th>Extra</th></tr></thead><tbody>${cols.map(c=>`<tr><td>${escapeHtml(c.COLUMN_NAME)}</td><td>${escapeHtml(c.COLUMN_TYPE)}</td><td>${escapeHtml(c.IS_NULLABLE)}</td><td>${escapeHtml(c.COLUMN_KEY||'')}</td><td>${escapeHtml(c.COLUMN_DEFAULT ?? 'NULL')}</td><td>${escapeHtml(c.EXTRA||'')}</td></tr>`).join('')}</tbody></table>`;
 } catch(e) { showToast('Yapı alınamadı: '+e.message,true); }
 }


 // JAVASCRIPT FONKSİYONU: Kullanıcının bilgisayarından SQL dosyası seçip sunucuya güvenli içe aktarma isteği gönderir.
async function importSqlFromComputer() {
 const fileInput = document.getElementById('dbSqlImportFile');
 const button = document.getElementById('dbSqlImportBtn');
 if (!fileInput || !button) return;

 fileInput.value = '';
 fileInput.click();

 const waitForSelection = () => new Promise(resolve => {
 const handler = () => {
 fileInput.removeEventListener('change', handler);
 resolve(fileInput.files?.[0] || null);
 };
 fileInput.addEventListener('change', handler, {once:true});
 });

 const file = await waitForSelection();
 if (!file) return;

 const name = file.name || 'sql-import.sql';
 const size = formatBytes(file.size || 0);
 const modeEl = document.getElementById('dbSqlImportMode');
 const importMode = modeEl?.value === 'soft' ? 'soft' : 'safe';
 const modeLabel = importMode === 'soft' ? 'Yumuşak Import' : 'Güvenli Import';
 const confirmMessage = importMode === 'soft'
 ? `“${name}” (${size}) Yumuşak Import ile uygulanacak. Bu mod mevcut tabloları/verileri değiştirebilir veya silebilir; trigger, event, procedure, function, view, index ve ALTER gibi veritabanı komutlarına daha geniş izin verir. CREATE/DROP DATABASE, USER/ROLE, GRANT/REVOKE, CALL, LOAD DATA, OUTFILE/DUMPFILE, SHUTDOWN, KILL ve benzeri sunucu yönetim komutları yine engellenir. Devam edilsin mi?`
 : `“${name}” (${size}) Güvenli Import ile uygulanacak. Mevcut tablolar ve diğer veritabanı nesneleri değiştirilemez veya silinemez; yeni oluşturulan nesneler üzerinde sonraki komutlara izin verilir. Devam edilsin mi?`;
 const confirmed = await showConfirm(
 confirmMessage,
 modeLabel,
 'Evet, içeri aktar'
 );
 if (!confirmed) return;

 const form = new FormData();
 form.append('csrf_token', CSRF_TOKEN);
 form.append('import_mode', importMode);
 form.append('sql_file', file, name);

 button.disabled = true;
 const oldText = button.textContent;
 button.textContent = 'SQL aktarılıyor...';
 showToast(`${modeLabel} başlatılıyor: ${name} (${size})`);

 try {
 const response = await fetch('?action=import_sql_upload', {
 method: 'POST',
 credentials: 'same-origin',
 cache: 'no-store',
 headers: {
 'X-CSRF-TOKEN': CSRF_TOKEN,
 'Accept': 'application/json'
 },
 body: form
 });

 const text = await response.text();
 let json;
 try {
 json = JSON.parse(text);
 } catch (e) {
 throw new Error(`Sunucudan geçersiz JSON yanıtı geldi (HTTP ${response.status}).`);
 }
 if (!json.success) throw new Error(json.message || 'SQL içeri aktarma başarısız.');

 const d = json.data || {};
 const resultMode = d.import_mode === 'soft' ? 'Yumuşak Import' : 'Güvenli Import';
 const summary = `${resultMode} • ${Number(d.queries || 0).toLocaleString()} sorgu işlendi • ${Number(d.success || 0).toLocaleString()} başarılı • ${Number(d.errors || 0).toLocaleString()} hatalı • ${Number(d.blocked || 0).toLocaleString()} güvenlik engeli`;
 if (Number(d.errors || 0) > 0 || Number(d.blocked || 0) > 0) {
 showToast(`Import tamamlandı fakat bazı sorgular hata verdi: ${summary}`, true);
 const details = Array.isArray(d.error_details) ? d.error_details : [];
 const blockedDetails = Array.isArray(d.blocked_details) ? d.blocked_details : [];
 if (details.length) console.error('SQL import hataları:', details);
 if (blockedDetails.length) console.warn('SQL import güvenlik engelleri:', blockedDetails);
 } else {
 showToast(`SQL import tamamlandı: ${summary}`);
 }

 await loadDatabaseTables(false);
 if (typeof loadDashboard === 'function') await loadDashboard();
 } catch (e) {
 console.error('SQL import:', e);
 showToast('SQL içeri aktarma hatası: ' + e.message, true);
 } finally {
 button.disabled = false;
 button.textContent = oldText;
 fileInput.value = '';
 }
 }

 // JAVASCRIPT FONKSİYONU: OPTIMIZE, ANALYZE gibi tablo bakım işlemlerini API üzerinden başlatır.
async function dbMaintenance(operation) {
 if (!dbSelectedTable) return showToast('Önce tablo seç.', true);
 try { const res = await apiRequest('db_table_maintenance',{table:dbSelectedTable,operation}); showToast(res.data?.message || res.message); loadDatabaseTables(false); }
 catch(e){ showToast('Bakım hatası: '+e.message,true); }
 }

 // JAVASCRIPT FONKSİYONU: TRUNCATE veya DROP gibi veri kaybı oluşturabilecek tablo işlemlerini onaydan sonra başlatır.
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
 // JAVASCRIPT FONKSİYONU: Cron için oluşturulan sabit PHP komutunu panoya kopyalar.
function copyCronCommand()
 {
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

 // Uzun işlemler için CLI arka plan işlem adımı ve Web arka plan işlem adımı kullanıcı tarafından seçilebilir.
 // CLI varsayılandır; WEB seçildiğinde mevcut Web arka plan işlem adımı akışı kullanılır.
 let selectedWorkerMode = 'cli';

 // JAVASCRIPT FONKSİYONU: Uzun işlerde kullanılacak CLI veya WEB çalışma modunu tarayıcı ayarından okur.
function getWorkerMode()
 {
 return selectedWorkerMode === 'web' ? 'web' : 'cli';
 }

 // JAVASCRIPT FONKSİYONU: Kullanıcının CLI/WEB çalışma modu tercihini tarayıcıya kaydeder.
function setWorkerMode(mode)
 {
 const normalized = String(mode || '').toLowerCase() === 'web' ? 'web' : 'cli';
 selectedWorkerMode = normalized;

 const cliCheckbox = document.getElementById('workerModeCli');
 const webCheckbox = document.getElementById('workerModeWeb');

 if (cliCheckbox) cliCheckbox.checked = normalized === 'cli';
 if (webCheckbox) {
 webCheckbox.checked = normalized === 'web';
 webCheckbox.disabled = false;
 }
 }

 // JAVASCRIPT FONKSİYONU: Seçilen çalışma modunun paneldeki açıklamasını günceller.
function updateWorkerModeStatus()
 {
 const status = document.getElementById('workerModeStatus');
 const cronBox = document.getElementById('cliCronBox');
 const advice = document.getElementById('workerModeAdvice');
 const mode = getWorkerMode();

 if (status) {
 status.textContent = mode === 'web' ? 'WEB Worker' : 'CLI arka plan worker';
 }

 // Cron yalnızca CLI arka plan işlem adımı ile ilişkilidir.
 if (cronBox) cronBox.style.display = mode === 'web' ? 'none' : '';

 if (advice) {
 advice.innerHTML = mode === 'web'
 ? '<strong>WEB Worker:</strong> Backup ve restore işlemleri mevcut Web Worker üzerinden tablo tablo ilerler. Sayfayı açık tutmanız gerekir.'
 : '<strong>CLI Worker:</strong> Backup ve restore işlemleri HTTP isteğinden bağımsız ayrı bir PHP CLI process içinde çalışır. Tarayıcı kapatılsa bile işlem devam eder.';
 }
 }

 document.getElementById('workerModeCli')?.addEventListener('change', function () {
 if (this.checked) setWorkerMode('cli');
 else if (!document.getElementById('workerModeWeb')?.checked) setWorkerMode('cli');
 updateWorkerModeStatus();
 });

 document.getElementById('workerModeWeb')?.addEventListener('change', function () {
 if (this.checked) setWorkerMode('web');
 else if (!document.getElementById('workerModeCli')?.checked) setWorkerMode('cli');
 updateWorkerModeStatus();
 });

 setWorkerMode('cli');
 updateWorkerModeStatus();

 // Tam yedekleme.
 let activeCliJobId = '';

 // JAVASCRIPT FONKSİYONU: Kullanıcının istediği tam veri tabanı yedeğini API üzerinden başlatır.
async function startFullBackup() {
 const workerMode = getWorkerMode();
 activeProgressEngine = workerMode;
 try {
 document.getElementById('live-progress-panel').style.display = 'block';
 const initialProgressTitle = document.getElementById('bg-progress-title');
 const initialProgressStatus = document.getElementById('bg-status-text');
 if (initialProgressTitle) initialProgressTitle.textContent = 'Canlı Yedekleme İlerlemesi';
 if (initialProgressStatus) initialProgressStatus.textContent = 'Yedekleme hazırlanıyor...';
 showToast('Yedekleme işlemi başlatılıyor...');
 cliJobStartedThisPage = true;
 const res = await apiRequest('run_full_backup', { worker_mode: workerMode });
 activeCliJobId = res?.data?.job_id || '';
 if (!activeCliJobId) throw new Error('Worker job ID alınamadı.');
 void logClientAction('Yedekleme başlatıldı', 'mod=' + workerMode.toUpperCase());
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

 // Canlı ilerleme durumunu düzenli olarak sorgula
 // ETA için backend değeri henüz oluşmamışsa yüzde + geçen süre üzerinden
 // istemci tarafında güvenli bir tahmin üret. Böylece emergency/restore gibi
 // ara fazlarda state alanı kısa süreli eksik olsa bile sayaç 'Hesaplanıyor...'
 // durumunda sonsuza kadar kalmaz.
 // JAVASCRIPT FONKSİYONU: Kalan süre tahminini kullanıcıya okunabilir biçimde gösterir.
function formatEta(seconds, status, percent, elapsedSeconds)
 {
 if (String(status || '').toLowerCase() === 'completed') return '0sn';

 const direct = Number(seconds);
 if (Number.isFinite(direct) && direct > 0) return formatDuration(direct);

 const pct = Math.max(0, Math.min(99.9, Number(percent) || 0));
 const elapsed = Math.max(0, Number(elapsedSeconds) || 0);
 if (pct > 0 && elapsed > 0) {
 const estimated = Math.max(1, Math.ceil(elapsed * ((100 - pct) / pct)));
 return formatDuration(estimated);
 }

 return 'Hesaplanıyor…';
 }

 // JAVASCRIPT FONKSİYONU: Süreyi saniye yerine saat/dakika/saniye gibi okunabilir biçime çevirir.
function formatDuration(seconds)
 {
 const total = Math.max(0, Math.floor(Number(seconds) || 0));
 const h = Math.floor(total / 3600);
 const m = Math.floor((total % 3600) / 60);
 const s = total % 60;
 return h > 0
 ? `${h}s ${String(m).padStart(2, '0')}dk ${String(s).padStart(2, '0')}sn`
 : `${m}dk ${String(s).padStart(2, '0')}sn`;
 }

 let progressUiRefs = null;
 let progressElapsedTicker = null;
 let progressElapsedJobId = '';
 let progressElapsedBase = 0;
 let progressElapsedSyncedAt = 0;
 let progressElapsedHasSync = false;

 // JAVASCRIPT FONKSİYONU: İlerleme ekranındaki süre sayacını durdurur.
function stopProgressElapsedTicker()
 {
 if (progressElapsedTicker) {
 clearInterval(progressElapsedTicker);
 progressElapsedTicker = null;
 }
 progressElapsedJobId = '';
 progressElapsedBase = 0;
 progressElapsedSyncedAt = 0;
 progressElapsedHasSync = false;
 }

 // JAVASCRIPT FONKSİYONU: Sunucunun bildirdiği geçen süre ile tarayıcıdaki sayacı eşitler.
function syncProgressElapsed(d)
 {
 const ui = getProgressUiRefs();
 if (!ui.elapsed) return;
 const jobId = String(d.job_id || activeCliJobId || '');
 const incoming = Math.max(0, Number(d.elapsed_seconds ?? d.duration_seconds ?? 0) || 0);
 const now = performance.now();

 if (d.status === 'completed' || d.status === 'failed') {
 if (progressElapsedTicker) {
 clearInterval(progressElapsedTicker);
 progressElapsedTicker = null;
 }
 progressElapsedJobId = jobId;
 progressElapsedBase = incoming;
 progressElapsedSyncedAt = now;
 progressElapsedHasSync = true;
 ui.elapsed.textContent = formatDuration(incoming);
 return;
 }

 const currentLive = (progressElapsedJobId === jobId && progressElapsedHasSync)
 ? progressElapsedBase + Math.max(0, (now - progressElapsedSyncedAt) / 1000)
 : 0;

 if (progressElapsedJobId !== jobId || !progressElapsedHasSync || incoming >= currentLive) {
 progressElapsedJobId = jobId;
 progressElapsedBase = incoming;
 progressElapsedSyncedAt = now;
 progressElapsedHasSync = true;
 }

 if (!progressElapsedTicker) {
 progressElapsedTicker = setInterval(() => {
 if (!progressUiRefs?.elapsed || !progressElapsedHasSync) return;
 const live = progressElapsedBase + Math.max(0, (performance.now() - progressElapsedSyncedAt) / 1000);
 progressUiRefs.elapsed.textContent = formatDuration(live);
 }, 250);
 }

 const live = progressElapsedBase + Math.max(0, (now - progressElapsedSyncedAt) / 1000);
 ui.elapsed.textContent = formatDuration(live);
 }

 // JAVASCRIPT FONKSİYONU: İlerleme ekranında kullanılacak DOM elemanlarını toplar.
function getProgressUiRefs()
 {
 if (progressUiRefs) return progressUiRefs;
 progressUiRefs = {
 panel: document.getElementById('live-progress-panel'),
 indicator: document.getElementById('bg-live-indicator'),
 title: document.getElementById('bg-progress-title'),
 status: document.getElementById('bg-status-text'),
 percent: document.getElementById('bg-percent-text'),
 bar: document.getElementById('bg-progress-bar'),
 activeTable: document.getElementById('bg-active-table'),
 tableIdx: document.getElementById('bg-table-idx'),
 rows: document.getElementById('bg-processed-rows'),
 speed: document.getElementById('bg-speed'),
 elapsed: document.getElementById('bg-elapsed'),
 eta: document.getElementById('bg-eta'),
 bytes: document.getElementById('bg-written-bytes'),
 badge: document.getElementById('bg-status-badge')
 };
 return progressUiRefs;
 }

 // JAVASCRIPT FONKSİYONU: Sunucudan gelen iş durumunu ilerleme çubuğu, yüzde ve mesajlara uygular.
function applyProgressState(d)
 {
 if (!d || d.status === 'idle') return;
 const ui = getProgressUiRefs();
 if (ui.indicator) {
 ui.indicator.className = 'bg-live-indicator';
 if (d.status === 'failed') ui.indicator.classList.add('error');
 else if (d.status === 'completed') ui.indicator.classList.add('success');
 else ui.indicator.classList.add('active');
 }

 if (ui.panel) ui.panel.style.display = 'block';
 const jobType = String(d.type || '').toLowerCase() === 'restore' ? 'restore' : 'backup';
 const jobLabel = jobType === 'restore' ? 'Restore' : 'Yedekleme';
 const progressTitle = ui.title;
 const progressStatus = ui.status;
 if (progressTitle) progressTitle.textContent = d.phase === 'emergency_backup' ? 'Emergency Snapshot İlerlemesi' : `Canlı ${jobLabel} İlerlemesi`;
 if (progressStatus) {
 if (d.status === 'failed') {
 progressStatus.textContent = d.error || d.message || `${jobLabel} başarısız.`;
 } else if (d.phase === 'emergency_backup') {
 const current = d.current_table || 'Hazırlanıyor';
 const idx = Number(d.current_table_index || 0);
 const total = Number(d.total_tables || 0);
 const rows = Number(d.processed_rows || 0).toLocaleString();
 progressStatus.textContent = `Emergency snapshot alınıyor: ${current} | ${total ? Math.min(total, idx) + '/' + total + ' tablo | ' : ''}${rows} satır`;
 } else if (d.type === 'restore' && d.phase === 'analyze') {
 const currentAnalyze = d.analyze_in_progress
 ? (d.analyze_running_table || d.analyze_current_table || d.current_table || '-')
 : (d.analyze_current_table || d.current_table || '-');
 const analyzeIndex = Number(d.analyze_index || 0);
 const analyzeTotal = Number(d.analyze_total || 0);
 const analyzeOk = Number(d.analyze_successful || 0);
 const analyzeFailed = Number(d.analyze_failed || 0);
 const analyzeElapsed = Number(d.analyze_elapsed_seconds || 0);
 const analyzeStep = Number(d.analyze_last_step_seconds || 0);
 progressStatus.textContent =
 `Tablolar analiz ediliyor: ${analyzeIndex}/${analyzeTotal} | Başarılı: ${analyzeOk} | Hatalı: ${analyzeFailed} | Aktif tablo: ${currentAnalyze} | Son adım: ${analyzeStep.toFixed(1)} sn | Toplam: ${formatDuration(analyzeElapsed)}`;
 } else {
 progressStatus.textContent =
 d.current_table ? `İşleniyor: ${d.current_table}` :
 d.status === 'failed' ? (d.error || `${jobLabel} başarısız.`) :
 (d.engine === 'web' ? `Web Worker ${jobLabel.toLowerCase()} çalışıyor...` : `${jobLabel} işlemi çalışıyor...`);
 }
 }
 const percent = Math.max(0, Math.min(100, Number(d.phase === 'emergency_backup' ? (d.emergency_percent ?? d.percent ?? 0) : (d.percent ?? 0))));
 if (ui.percent) ui.percent.textContent = percent + '%';
 if (ui.bar) ui.bar.style.width = percent + '%';

 if (ui.activeTable) {
 if (d.status === 'completed') ui.activeTable.textContent = 'Tamamlandı';
 else if (d.phase === 'emergency_backup') ui.activeTable.textContent = d.current_table || 'Emergency snapshot';
 else if (d.type === 'restore' && d.phase === 'analyze') ui.activeTable.textContent = d.analyze_running_table || d.analyze_current_table || d.current_table || 'Tablolar analiz ediliyor';
 else if (d.current_table && !/\.sql\.gz$/i.test(String(d.current_table))) ui.activeTable.textContent = String(d.current_table);
 else ui.activeTable.textContent = '-';
 }
 if (ui.tableIdx) ui.tableIdx.textContent = d.total_tables ? `${d.current_table_index || 0} / ${d.total_tables}` : '-';
 if (ui.rows) ui.rows.textContent = (d.processed_rows || d.rows_count || 0).toLocaleString();
 if (ui.speed) ui.speed.textContent = d.formatted_speed || (d.speed_mb_per_second ? `${d.speed_mb_per_second} MB/sn` : `${(d.speed_rows_per_second || 0).toLocaleString()} satır/sn`);
 syncProgressElapsed(d);
 if (ui.eta) ui.eta.textContent = formatEta(d.estimated_remaining_seconds, d.status, d.phase === 'emergency_backup' ? (d.emergency_percent ?? d.percent ?? 0) : (d.percent ?? 0), d.elapsed_seconds ?? d.duration_seconds ?? 0);
 if (ui.bytes) ui.bytes.textContent = d.formatted_bytes || d.formatted_processed || (d.size ? formatBytes(d.size) : '0 B');
 }

 // JAVASCRIPT FONKSİYONU: Devam eden yedek/geri yükleme işinin durumunu belirli aralıklarla sunucudan sorar.
function startProgressPolling()
 {
 stopProgressPolling();
 // WEB modunda get_cli_job_progress zaten arka plan işlem adımı adımını yürütür;
 // ikinci bir hafif sorgu döngüsü açmak gereksiz ağ ve PHP yükü oluşturuyordu.
 const poll = async () => {
 if (!activeCliJobId) {
 progressInterval = null;
 return;
 }
 await fetchProgress();
 if (activeCliJobId) progressInterval = setTimeout(poll, 700);
 else progressInterval = null;
 };
 progressInterval = setTimeout(poll, 0);
 }
 // JAVASCRIPT FONKSİYONU: İlerleme durumu için yapılan periyodik sorgulamayı durdurur.
function stopProgressPolling()
 {
 if (progressInterval) {
 clearTimeout(progressInterval);
 progressInterval = null;
 }
 const liveIndicator = document.getElementById('bg-live-indicator');
 if (liveIndicator) liveIndicator.className = 'bg-live-indicator';
 if (!activeCliJobId) stopProgressElapsedTicker();
 }

 // JAVASCRIPT FONKSİYONU: Tek bir ilerleme durumu sorgusu yapar ve sonucu arayüze uygular.
async function fetchProgress() {
 try {
 if (!activeCliJobId) return;

 const res = await apiRequest('get_cli_job_progress', { job_id: activeCliJobId });
 const d = res.data;
 if (!d || d.status === 'idle') return;

 // İlerleme ekranının bütün ortak alanları tek noktadan güncellenir.
 // Böylece aynı DOM elemanlarının iki kez yazılması ve gereksiz layout hesapları önlenir.
 applyProgressState(d);
 const ui = getProgressUiRefs();

 if (d.status === 'completed') {
 const completedType = String(d.type || '').toLowerCase() === 'restore' ? 'restore' : 'backup';
 const completedLabel = completedType === 'restore' ? 'Restore' : 'Yedekleme';
 if (ui.title) ui.title.textContent = `Canlı ${completedLabel} İlerlemesi`;
 if (ui.status) {
 if (completedType === 'restore' && d.analyze_total !== undefined) {
 const analyzeTotal = Number(d.analyze_total || 0);
 const analyzeOk = Number(d.analyze_successful || 0);
 const analyzeFailed = Number(d.analyze_failed || 0);
 ui.status.textContent = analyzeFailed > 0
 ? `Restore tamamlandı — ANALYZE: ${analyzeOk}/${analyzeTotal} başarılı, ${analyzeFailed} başarısız`
 : `Restore ve ANALYZE tamamlandı — ${analyzeOk}/${analyzeTotal} tablo analiz edildi`;
 } else {
 ui.status.textContent = `${completedLabel} tamamlandı`;
 }
 }
 if (ui.badge) {
 ui.badge.className = 'badge badge-success';
 ui.badge.textContent = 'TAMAMLANDI';
 }
 stopProgressPolling();
 activeCliJobId = '';
 stopProgressElapsedTicker();
 void loadDashboard();
 return;
 }

 if (d.status === 'failed') {
 const failedType = String(d.type || '').toLowerCase() === 'restore' ? 'restore' : 'backup';
 const failedLabel = failedType === 'restore' ? 'Restore' : 'Yedekleme';
 if (ui.title) ui.title.textContent = `Canlı ${failedLabel} İlerlemesi`;
 if (ui.status && !d.error) ui.status.textContent = `${failedLabel} başarısız`;
 if (ui.badge) {
 ui.badge.className = 'badge badge-danger';
 ui.badge.textContent = 'HATA';
 }
 stopProgressPolling();
 stopProgressElapsedTicker();
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
 return;
 }

 if (ui.badge) {
 ui.badge.className = 'badge badge-warning';
 ui.badge.textContent = d.engine === 'web' ? 'WEB WORKER' : 'CLI ÇALIŞIYOR';
 }
 } catch (e) {
 // Geçici ağ/HTTP hatasında arka plan işlem adımı durdurulmaz; sonraki polling tekrar dener.
 }
 }

 // Yedek dosyasını indir
 // JAVASCRIPT FONKSİYONU: Seçilen yedek dosyasını sunucudan güvenli indirme isteğiyle indirir.
async function downloadFile(file) {
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
 void logClientAction('Yedek indirildi', String(file || ''));
 } catch (err) {
 showToast('İndirme hatası: ' + err.message, true);
 }
 }

 // JAVASCRIPT FONKSİYONU: Tek bir yedek dosyasını kullanıcı onayından sonra siler.
async function deleteFile(file) {
 const confirmed = await showConfirm(
 `“${file}” yedek dosyası kalıcı olarak silinecek.`,
 'Yedeği sil',
 'Evet, sil'
 );
 if (!confirmed) return;

 try {
 await apiRequest('delete_backup', { file: file });
 void logClientAction('Yedek silindi', String(file || ''));
 showToast('Yedek dosyası silindi.');
 loadDashboard();
 } catch (err) {
 showToast('Silme hatası: ' + err.message, true);
 }
 }

 // JAVASCRIPT FONKSİYONU: Seçilen yedeğin bütünlük/kontrol işlemini sunucuda başlatır.
async function verifyFile(file) {
 showToast(`'${file}' için bütünlük doğrulaması başlatılıyor...`);
 try {
 const res = await apiRequest('check_integrity', { file: file });
 const d = res?.data || {};
 void logClientAction('Yedek bütünlük kontrolü', String(file || ''));
 if (d.async && d.job_id) {
 showToast(`'${file}' bütünlük kontrolü arka planda çalışıyor...`);
 const poll = async () => {
 try {
 const p = await apiRequest('get_cli_job_progress', { job_id: d.job_id });
 const s = p?.data || {};
 if (s.status === 'completed') {
 showToast(`BAŞARILI: ${s.message || 'Bütünlük + test restore doğrulaması tamamlandı.'}`);
 loadDashboard();
 return;
 }
 if (s.status === 'failed') {
 showToast('Bütünlük Hatası: ' + (s.error || 'Doğrulama başarısız.'), true);
 return;
 }
 setTimeout(poll, 900);
 } catch (e) {
 setTimeout(poll, 1500);
 }
 };
 setTimeout(poll, 300);
 return;
 }
 showToast(`BAŞARILI: ${res.message}`);
 loadDashboard();
 } catch (err) {
 showToast('Bütünlük Hatası: ' + err.message, true);
 }
 }

 // RESTORE: seçilen yedekten geri yükleme işlemini başlatır
 // JAVASCRIPT FONKSİYONU: Seçilen yedek dosyasından veri tabanı geri yükleme işlemini başlatır.
async function triggerRestore(file) {
 const workerMode = getWorkerMode();
 activeProgressEngine = workerMode;
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
 const initialProgressTitle = document.getElementById('bg-progress-title');
 const initialProgressStatus = document.getElementById('bg-status-text');
 if (initialProgressTitle) initialProgressTitle.textContent = 'Canlı Restore İlerlemesi';
 if (initialProgressStatus) initialProgressStatus.textContent = 'Restore hazırlanıyor...';
 showToast(`'${file}' restore işlemi başlatılıyor...`);
 cliJobStartedThisPage = true;

 try {
 const res = await apiRequest('restore_chunk', { file: file, worker_mode: workerMode });
 void logClientAction('Restore başlatıldı', String(file || '') + ' | mod=' + workerMode.toUpperCase());
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

 // Log sistemi
 // JAVASCRIPT FONKSİYONU: Bir log alanının görünür veya seçili durumda olup olmadığını kontrol eder.
function hasLogSelection(element)
 {
 if (!element || !window.getSelection) return false;
 const selection = window.getSelection();
 if (!selection || selection.isCollapsed || selection.rangeCount === 0) return false;
 const anchor = selection.anchorNode;
 const focus = selection.focusNode;
 return !!((anchor && element.contains(anchor)) || (focus && element.contains(focus)));
 }
 // JAVASCRIPT FONKSİYONU: Sunucudan gelen log içeriğini ilgili log kutularına yerleştirir.
function renderLogBoxes(html)
 {
 const logBox = document.getElementById('logBoxContainer');
 const modalBox = document.getElementById('logModalBox');
 if (!logBox) return;

 // Kullanıcı mavi seçim yapıyorsa innerHTML değiştirilmez; aksi halde seçim anında kaybolur.
 if (hasLogSelection(logBox) || hasLogSelection(modalBox)) return;

 // İçerik değişmediyse DOM'yi hiç yeniden oluşturma.
 if (logBox.innerHTML === html && (!modalBox || modalBox.innerHTML === html)) return;

 logBox.innerHTML = html;
 // Yeni işlem sonrası en son log satırını göster.
 // Periyodik yenileme yok; kullanıcı logu rahatça seçip kopyalayabilir.
 logBox.scrollTop = logBox.scrollHeight;

 const modalOverlay = document.getElementById('logModalOverlay');
 if (modalBox && modalOverlay?.classList.contains('open')) {
 modalBox.innerHTML = html;
 modalBox.scrollTop = modalBox.scrollHeight;
 }
 }

 // Log sistemi
 // JAVASCRIPT FONKSİYONU: Log ekranındaki filtreye göre görünen kayıtları azaltır.
function filterLogs()
 {
 const search = document.getElementById('logSearch').value.toLowerCase();
 const level = document.getElementById('logLevelFilter').value;
 const logBox = document.getElementById('logBoxContainer');

 if (!rawLogLines || rawLogLines.length === 0) {
 if (!hasLogSelection(logBox)) logBox.textContent = 'Henüz log kaydı yok.';
 const modalBox = document.getElementById('logModalBox');
 const modalOverlay = document.getElementById('logModalOverlay');
 if (modalBox && modalOverlay?.classList.contains('open') && !hasLogSelection(modalBox)) modalBox.textContent = 'Henüz log kaydı yok.';
 return;
 }

 const filtered = rawLogLines.filter(line => {
 const matchesSearch = line.toLowerCase().includes(search);
 const matchesLevel = (level === 'ALL') || line.includes(`[${level}]`);
 return matchesSearch && matchesLevel;
 });

 if (filtered.length === 0) {
 if (!hasLogSelection(logBox)) logBox.textContent = 'Filtrelere uygun log bulunamadı.';
 const modalBox = document.getElementById('logModalBox');
 const modalOverlay = document.getElementById('logModalOverlay');
 if (modalBox && modalOverlay?.classList.contains('open') && !hasLogSelection(modalBox)) modalBox.textContent = 'Filtrelere uygun log bulunamadı.';
 return;
 }

 const html = filtered.map(line => {
 const cls = logLineClass(line);
 return `<div class="${cls}">${escapeHtml(line)}</div>`;
 }).join('');

 renderLogBoxes(html);
 }
 let logEventSource = null;
 let logStreamReconnectTimer = null;

 // JAVASCRIPT FONKSİYONU: Yeni gelen canlı log satırını ilgili kutunun sonuna ekler.
function appendRealtimeLogLineToBox(box, line)
 {
 if (!box || typeof line !== 'string' || line === '') return;
 const item = document.createElement('div');
 item.className = logLineClass(line);
 item.textContent = line;
 box.appendChild(item);
 box.scrollTop = box.scrollHeight;
 }

 // JAVASCRIPT FONKSİYONU: Canlı log kaydını paneldeki log alanlarına dağıtır ve tampon sınırını korur.
function addRealtimeLogLine(line)
 {
 if (typeof line !== 'string' || line === '') return;
 // Aynı son satırın SSE reconnect sırasında ikinci kez eklenmesini önle.
 const last = rawLogLines.length ? rawLogLines[rawLogLines.length - 1] : '';
 if (line === last) return;
 rawLogLines.push(line);
 if (rawLogLines.length > MAX_CLIENT_LOG_LINES) {
 rawLogLines.splice(0, rawLogLines.length - MAX_CLIENT_LOG_LINES);
 }

 const searchEl = document.getElementById('logSearch');
 const levelEl = document.getElementById('logLevelFilter');
 const search = searchEl ? searchEl.value.trim().toLowerCase() : '';
 const level = levelEl ? levelEl.value : 'ALL';

 // Filtre yoksa mevcut DOM'yi baştan üretme. Yeni satırı terminal gibi tek seferde ekle.
 if (search === '' && level === 'ALL') {
 appendRealtimeLogLineToBox(document.getElementById('logBoxContainer'), line);
 const modalOverlay = document.getElementById('logModalOverlay');
 if (modalOverlay?.classList.contains('open')) {
 appendRealtimeLogLineToBox(document.getElementById('logModalBox'), line);
 }
 return;
 }

 // Filtre aktifse doğru görünümü yeniden üretmek gerekir.
 filterLogs();
 }

 // JAVASCRIPT FONKSİYONU: SSE bağlantısı açarak sunucudan gelen logları anlık olarak dinler.
function startRealtimeLogStream()
 {
 if (!window.EventSource || logEventSource) return;
 // GET yalnızca log okur ve oturum kontrolü sunucu tarafında yapılır.
 // CSRF token'ı URL'ye taşımıyoruz; böylece access/proxy loglarına sızma riski kaldırılır.
 const streamUrl = '?action=log_stream';
 try {
 logEventSource = new EventSource(streamUrl, { withCredentials: true });

 logEventSource.addEventListener('init', (event) => {
 try {
 const payload = JSON.parse(event.data || '{}');
 if (Array.isArray(payload.lines)) {
 rawLogLines = normalizeClientLogLines(payload.lines);
 filterLogs();
 }
 } catch (e) {
 console.error('Canlı log başlangıç verisi okunamadı:', e);
 }
 });

 logEventSource.addEventListener('replace', (event) => {
 try {
 const payload = JSON.parse(event.data || '{}');
 if (Array.isArray(payload.lines)) {
 rawLogLines = normalizeClientLogLines(payload.lines);
 filterLogs();
 }
 } catch (e) {
 console.error('Canlı log yenileme verisi okunamadı:', e);
 }
 });

 logEventSource.addEventListener('line', (event) => {
 try {
 const payload = JSON.parse(event.data || '{}');
 addRealtimeLogLine(payload.line);
 } catch (e) {
 console.error('Canlı log satırı okunamadı:', e);
 }
 });

 logEventSource.onerror = () => {
 // EventSource bağlantısı sunucu tarafından 25 sn sonra bilinçli kapatılır;
 // tarayıcı otomatik yeniden bağlanır. Manuel timer yalnızca tamamen kapalı durumda gerekir.
 if (logEventSource && logEventSource.readyState === EventSource.CLOSED) {
 logEventSource.close();
 logEventSource = null;
 if (!logStreamReconnectTimer) {
 logStreamReconnectTimer = setTimeout(() => {
 logStreamReconnectTimer = null;
 startRealtimeLogStream();
 }, 250);
 }
 }
 };
 } catch (e) {
 logEventSource = null;
 }
 }

 // JAVASCRIPT FONKSİYONU: Log satırının seviyesine göre kullanılacak CSS sınıfını belirler.
function logLineClass(line)
 {
 if (line.includes('[SUCCESS]')) return 'log-line-SUCCESS';
 if (line.includes('[INFO]')) return 'log-line-INFO';
 if (line.includes('[WARNING]')) return 'log-line-WARNING';
 if (line.includes('[ERROR]')) return 'log-line-ERROR';
 return '';
 }

 // JAVASCRIPT FONKSİYONU: Sunucudaki logları kullanıcı onayıyla temizler.
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
 // JAVASCRIPT FONKSİYONU: Tarayıcı tarafında yapılan önemli kullanıcı hareketlerini sunucu loguna bildirir.
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

 // JAVASCRIPT FONKSİYONU: CPU/RAM/disk gibi ölçümlerin gösterge çubuğunu ve değerini günceller.
function setServerGauge(id, value, valueId, metaId, metaText)
 {
 const pct = Math.max(0, Math.min(100, Number(value) || 0));
 const gauge = document.getElementById(id);
 const valueEl = document.getElementById(valueId);
 const metaEl = document.getElementById(metaId);
 if (gauge) gauge.style.setProperty('--gauge-value', pct + '%');
 if (valueEl) valueEl.textContent = Math.round(pct) + '%';
 if (metaEl) metaEl.textContent = metaText || '';
 }

 // JAVASCRIPT FONKSİYONU: Sunucu kaynak bilgilerinden HTML tablo oluşturur.
 // JAVASCRIPT FONKSİYONU: Sunucu metriklerini dashboard kartlarına ve bilgi pencerelerine dağıtır.
function renderServerInfoTable(id, entries)
 {
 const el = document.getElementById(id);
 if (!el) return;
 el.innerHTML = entries.map(([key, value]) =>
 `<div class="server-info-row"><div class="server-info-key">${escapeHtml(key)}</div><div class="server-info-value">${escapeHtml(value ?? 'N/A')}</div></div>`
 ).join('');
 }

 // JAVASCRIPT FONKSİYONU: Açık olan sunucu bilgi penceresindeki kaynak verilerini yeniler.
function refreshOpenServerInfoResources()
 {
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

 function renderServerInfo(metrics)
 {
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

 // JAVASCRIPT FONKSİYONU: Sunucu kaynak ayrıntılarını gösteren pencereyi açar.
function openServerInfo()
 {
 const overlay = document.getElementById('serverInfoOverlay');
 if (!overlay) return;
 overlay.classList.add('open');
 overlay.setAttribute('aria-hidden', 'false');
 if (latestServerMetrics) {
 renderServerInfo(latestServerMetrics);
 } else {
 loadDashboard();
 }
 }

 // JAVASCRIPT FONKSİYONU: Sunucu kaynak ayrıntı penceresini kapatır.
function closeServerInfo()
 {
 const overlay = document.getElementById('serverInfoOverlay');
 if (!overlay) return;
 overlay.classList.remove('open');
 overlay.setAttribute('aria-hidden', 'true');
 }

 // JAVASCRIPT FONKSİYONU: PHP çalışma ortamı hakkındaki bilgileri gösteren pencereyi açar.
function openPhpInfo()
 {
 const overlay = document.getElementById('phpInfoOverlay');
 const frame = document.getElementById('phpInfoFrame');
 const loading = document.getElementById('phpInfoLoading');
 if (!overlay || !frame) return;

 overlay.classList.add('open');
 overlay.setAttribute('aria-hidden', 'false');
 if (loading) {
 loading.textContent = 'PHP bilgileri yükleniyor...';
 loading.classList.remove('hidden');
 }

 // Aynı popup tekrar açıldığında eski belge gösterilmesin.
 frame.srcdoc = '';

 const requestBody = new URLSearchParams();
 requestBody.set('action', 'php_info');
 requestBody.set('csrf_token', CSRF_TOKEN);

 fetch(window.location.href, {
 method: 'POST',
 credentials: 'same-origin',
 headers: {
 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
 'X-CSRF-TOKEN': CSRF_TOKEN,
 'Accept': 'text/html'
 },
 body: requestBody.toString()
 })
 .then(async (response) => {
 const html = await response.text();
 if (!response.ok) {
 throw new Error(html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() || 'PHP bilgileri alınamadı.');
 }
 frame.srcdoc = html;
 frame.onload = () => {
 if (loading) loading.classList.add('hidden');
 };
 })
 .catch((error) => {
 if (loading) {
 loading.textContent = error?.message || 'PHP bilgileri alınamadı.';
 }
 });
 }

 // JAVASCRIPT FONKSİYONU: PHP bilgi penceresini kapatır.
function closePhpInfo()
 {
 const overlay = document.getElementById('phpInfoOverlay');
 const frame = document.getElementById('phpInfoFrame');
 if (!overlay) return;
 overlay.classList.remove('open');
 overlay.setAttribute('aria-hidden', 'true');
 if (frame) frame.srcdoc = '';
 }

 let liveMetricsTimer = null;
 let liveMetricsBusy = false;

 let liveMetricUiRefs = null;
 // JAVASCRIPT FONKSİYONU: Canlı CPU/RAM/disk göstergelerinin DOM elemanlarını toplar.
function getLiveMetricUiRefs()
 {
 if (liveMetricUiRefs) return liveMetricUiRefs;
 liveMetricUiRefs = {
 cpuPct: document.getElementById('m-cpu-pct'), cpuLoad: document.getElementById('m-cpu-load'), cpuCores: document.getElementById('m-cpu-cores'), cpuBar: document.getElementById('m-cpu-bar'),
 ramPct: document.getElementById('m-ram-pct'), ramUsed: document.getElementById('m-ram-used'), ramTotal: document.getElementById('m-ram-total'), ramBar: document.getElementById('m-ram-bar'),
 diskPct: document.getElementById('m-disk-pct'), diskFree: document.getElementById('m-disk-free'), diskTotal: document.getElementById('m-disk-total'), diskBar: document.getElementById('m-disk-bar'),
 serverOverlay: document.getElementById('serverInfoOverlay')
 };
 return liveMetricUiRefs;
 }

 // JAVASCRIPT FONKSİYONU: Sunucu kaynaklarını periyodik olarak yenileyip canlı göstergelere aktarır.
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

 const ui = getLiveMetricUiRefs();
 const cpuPctEl = ui.cpuPct;
 const cpuLoadEl = ui.cpuLoad;
 const cpuCoresEl = ui.cpuCores;
 const cpuBar = ui.cpuBar;
 const ramPctEl = ui.ramPct;
 const ramUsedEl = ui.ramUsed;
 const ramTotalEl = ui.ramTotal;
 const ramBar = ui.ramBar;
 const diskPctEl = ui.diskPct;
 const diskFreeEl = ui.diskFree;
 const diskTotalEl = ui.diskTotal;
 const diskBar = ui.diskBar;

 if (cpuPctEl) cpuPctEl.textContent = cpuPct + '%';
 if (cpuLoadEl) cpuLoadEl.textContent = Number(cpu.load_1min || 0).toFixed(2);
 if (cpuCoresEl) cpuCoresEl.textContent = cpu.cores || 1;
 if (cpuBar) cpuBar.style.width = cpuPct + '%';

 if (ramPctEl) ramPctEl.textContent = ramPct + '%';
 if (ramUsedEl) ramUsedEl.textContent = formatBytes(ram.used);
 if (ramTotalEl) ramTotalEl.textContent = formatBytes(ram.total);
 if (ramBar) ramBar.style.width = ramPct + '%';

 if (diskPctEl) diskPctEl.textContent = diskPct + '%';
 if (diskFreeEl) diskFreeEl.textContent = formatBytes(disk.free);
 if (diskTotalEl) diskTotalEl.textContent = formatBytes(disk.total);
 if (diskBar) diskBar.style.width = diskPct + '%';

 // Sunucu Bilgisi açıksa dairesel göstergeleri aynı canlı veriden güncelle.
 setServerGauge('serverGaugeCpu', cpuPct, 'serverGaugeCpuValue', 'serverGaugeCpuMeta',
 'Load ' + Number(cpu.load_1min || 0).toFixed(2) + ' · ' + (cpu.cores || 1) + ' çekirdek');
 setServerGauge('serverGaugeRam', ramPct, 'serverGaugeRamValue', 'serverGaugeRamMeta',
 formatBytes(ram.used) + ' / ' + formatBytes(ram.total));
 setServerGauge('serverGaugeDisk', diskPct, 'serverGaugeDiskValue', 'serverGaugeDiskMeta',
 formatBytes(disk.used) + ' / ' + formatBytes(disk.total));

 // Sunucu Bilgisi açıksa mevcut render mekanizmasını da güncelle.
 if (typeof latestServerMetrics === 'object' && latestServerMetrics) {
 latestServerMetrics.cpu = Object.assign({}, latestServerMetrics.cpu, cpu);
 latestServerMetrics.ram = Object.assign({}, latestServerMetrics.ram, ram);
 latestServerMetrics.disk = Object.assign({}, latestServerMetrics.disk, disk);
 const serverInfoOverlay = ui.serverOverlay;
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
 liveMetricsTimer = setTimeout(refreshLiveMetrics, LIVE_METRICS_INTERVAL_MS);
 }
 }
 }

 // JAVASCRIPT FONKSİYONU: Canlı kaynak ölçümlerinin düzenli yenilenmesini başlatır.
function startLiveMetrics(immediate = false)
 {
 clearTimeout(liveMetricsTimer);
 liveMetricsTimer = null;
 if (immediate) {
 refreshLiveMetrics();
 } else if (!document.hidden) {
 liveMetricsTimer = setTimeout(refreshLiveMetrics, LIVE_METRICS_INTERVAL_MS);
 }
 }

 document.addEventListener('visibilitychange', () => {
 if (!document.hidden) startLiveMetrics(true);
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

 // Dinamik butonlar için tek document seviyesinde click dinleyicisi kullanılır.
 // Böylece iki ayrı bubbling dinleyicisinin her tıklamada ayrı ayrı çalışması önlenir.
 document.addEventListener('click', (event) => {
 const bulkBtn = event.target?.closest?.('#bulkDeleteBackupsBtn');
 if (bulkBtn) {
 event.preventDefault();
 event.stopPropagation();
 if (!bulkBtn.disabled) bulkDeleteBackups();
 return;
 }

 const emptyBtn = event.target?.closest?.('#dbEmptyDatabaseBtn');
 if (emptyBtn) {
 event.preventDefault();
 if (!emptyBtn.disabled) emptyEntireDatabase();
 }
 });

 const runBtn = document.getElementById('btnRunBackup');
 const openServerInfoBtn = document.getElementById('btnOpenServerInfo');
 const closeServerInfoBtn = document.getElementById('btnCloseServerInfo');
 const refreshServerInfoBtn = document.getElementById('btnRefreshServerInfo');
 const serverInfoOverlay = document.getElementById('serverInfoOverlay');
 const phpVersionLink = document.getElementById('m-php-ver');
 const phpInfoOverlay = document.getElementById('phpInfoOverlay');
 const closePhpInfoBtn = document.getElementById('btnClosePhpInfo');

 if (openServerInfoBtn) openServerInfoBtn.addEventListener('click', openServerInfo);
 if (phpVersionLink) {
 phpVersionLink.addEventListener('click', (event) => {
 event.preventDefault();
 openPhpInfo();
 });
 }
 if (closePhpInfoBtn) closePhpInfoBtn.addEventListener('click', closePhpInfo);
 if (phpInfoOverlay) {
 phpInfoOverlay.addEventListener('click', (event) => {
 if (event.target === phpInfoOverlay) closePhpInfo();
 });
 }
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
 if (event.key !== 'Escape') return;
 if (document.getElementById('serverInfoOverlay')?.classList.contains('open')) closeServerInfo();
 if (document.getElementById('phpInfoOverlay')?.classList.contains('open')) closePhpInfo();
 if (document.getElementById('vedoConfirmOverlay')?.classList.contains('open')) closeConfirm(false);
 if (logModalOverlay?.classList.contains('open')) {
 logModalOverlay.classList.remove('open');
 logModalOverlay.setAttribute('aria-hidden', 'true');
 }
 if (dbExplorerOverlay?.classList.contains('open')) closeDbExplorer();
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
 // JAVASCRIPT FONKSİYONU: Veri tabanı gezgini penceresini açar.
function openDbExplorer()
 {
 if (!dbExplorerOverlay) return;
 dbExplorerOverlay.classList.add('open');
 dbExplorerOverlay.setAttribute('aria-hidden', 'false');
 document.body.classList.add('db-modal-open');
 if (typeof loadDatabaseTables === 'function' && !dbExplorerLoaded) {
 loadDatabaseTables(true);
 }
 }
 // JAVASCRIPT FONKSİYONU: Veri tabanı gezgini penceresini kapatır.
function closeDbExplorer()
 {
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
 const dbList = document.getElementById('dbTableList');
 if (dbList) dbList.addEventListener('click', (e) => { const item = e.target.closest('[data-db-table]'); if (item) selectDatabaseTable(item.dataset.dbTable); });
 document.getElementById('dbStructureBtn')?.addEventListener('click', loadDatabaseStructure);
 document.getElementById('dbAnalyzeBtn')?.addEventListener('click', () => dbMaintenance('analyze'));
 document.getElementById('dbRepairBtn')?.addEventListener('click', () => dbMaintenance('repair'));
 document.getElementById('dbOptimizeBtn')?.addEventListener('click', () => dbMaintenance('optimize'));
 document.getElementById('dbTruncateBtn')?.addEventListener('click', () => dbDestructive('truncate'));
 document.getElementById('dbDropBtn')?.addEventListener('click', () => dbDestructive('drop'));
 document.getElementById('dbRefreshBtn')?.addEventListener('click', () => loadDatabaseTables(false));
 document.getElementById('dbSqlImportBtn')?.addEventListener('click', importSqlFromComputer);
 document.getElementById('dbPrevBtn')?.addEventListener('click', () => { if (dbOffset >= DB_PAGE_SIZE) { dbOffset -= DB_PAGE_SIZE; loadDatabaseTableData(); } });
 document.getElementById('dbNextBtn')?.addEventListener('click', () => { dbOffset += DB_PAGE_SIZE; loadDatabaseTableData(); });

 // Dinamik backup satırları için tek olay dinleyicisi kullanılır (CSP uyumludur).
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
 // Log ekranı açık/kapalı olsun, sistem loglarını terminal benzeri gerçek zamanlı dinle.
 startRealtimeLogStream();
 startLiveMetrics();
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
