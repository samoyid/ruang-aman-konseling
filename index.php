<?php
session_name('RUANGAMANSESSID');

if (session_status() !== PHP_SESSION_ACTIVE) {
    $isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);

    session_start();
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

$cspNonce = base64_encode(random_bytes(16));
header(
    "Content-Security-Policy: " .
    "default-src 'self'; " .
    "base-uri 'self'; " .
    "object-src 'none'; " .
    "frame-ancestors 'self'; " .
    "form-action 'self'; " .
    "img-src 'self' data:; " .
    "style-src 'nonce-{$cspNonce}'; " .
    "script-src 'nonce-{$cspNonce}'; " .
    "connect-src 'self'; " .
    "font-src 'self';"
);

mysqli_report(MYSQLI_REPORT_OFF);
$conn = mysqli_connect('localhost', 'root', '', 'ruangaman');

if (!$conn) {
    http_response_code(500);
    exit('Koneksi database gagal. Pastikan MySQL aktif dan database "ruangaman" tersedia.');
}

if (!mysqli_set_charset($conn, 'utf8mb4')) {
    http_response_code(500);
    exit('Database gagal menggunakan UTF-8.');
}

$requiredTables = ['tb_user', 'tb_laporan'];
foreach ($requiredTables as $table) {
    $safeTable = mysqli_real_escape_string($conn, $table);
    $check = mysqli_query($conn, "SHOW TABLES LIKE '$safeTable'");
    if (!$check || mysqli_num_rows($check) === 0) {
        http_response_code(500);
        exit('Tabel database belum lengkap. Pastikan tb_user dan tb_laporan sudah dibuat.');
    }
}

const SESSION_TIMEOUT = 1800;
const LOGIN_WINDOW = 600;
const LOGIN_MAX_ATTEMPTS = 5;
const MAX_REPORT_LENGTH = 5000;

function e($value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

function redirect(string $url): void
{
    header('Location: ' . $url);
    exit;
}

function isLoggedIn(): bool
{
    return isset($_SESSION['user_id'], $_SESSION['role'], $_SESSION['login'])
        && $_SESSION['login'] === true;
}

function requireLogin(): void
{
    if (!isLoggedIn()) {
        redirect('index.php');
    }
}

function requireRole(string $role): void
{
    requireLogin();

    if ($_SESSION['role'] !== $role) {
        redirect($_SESSION['role'] === 'bk' ? 'index.php?page=bk' : 'index.php?page=siswa');
    }
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(): void
{
    $token = (string)($_POST['csrf_token'] ?? '');

    if ($token === '' || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        exit('Permintaan ditolak. Token keamanan tidak valid.');
    }
}

function cleanLoginAttempts(): void
{
    if (!isset($_SESSION['login_attempts']) || !is_array($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = [];
    }

    $now = time();
    $_SESSION['login_attempts'] = array_values(array_filter(
        $_SESSION['login_attempts'],
        static fn($timestamp) => ($now - (int)$timestamp) < LOGIN_WINDOW
    ));
}

function tooManyLoginAttempts(): bool
{
    cleanLoginAttempts();
    return count($_SESSION['login_attempts']) >= LOGIN_MAX_ATTEMPTS;
}

function registerFailedLogin(): void
{
    cleanLoginAttempts();
    $_SESSION['login_attempts'][] = time();
}

function valueLength(string $value): int
{
    return function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : strlen($value);
}

function validDate(string $date): bool
{
    $dateObject = DateTime::createFromFormat('Y-m-d', $date);
    if (!$dateObject || $dateObject->format('Y-m-d') !== $date) {
        return false;
    }

    return $dateObject <= new DateTime('today');
}

function formatDateId(?string $date): string
{
    if (!$date) {
        return '-';
    }

    $months = [
        1 => 'Jan', 2 => 'Feb', 3 => 'Mar', 4 => 'Apr',
        5 => 'Mei', 6 => 'Jun', 7 => 'Jul', 8 => 'Agu',
        9 => 'Sep', 10 => 'Okt', 11 => 'Nov', 12 => 'Des'
    ];

    $time = strtotime($date);
    if (!$time) {
        return '-';
    }

    return date('d', $time) . ' ' . $months[(int)date('n', $time)] . ' ' . date('Y', $time);
}

function formatDateTimeId(?string $dateTime): string
{
    if (!$dateTime) {
        return '-';
    }

    $time = strtotime($dateTime);
    return $time ? date('d/m/Y H:i', $time) : '-';
}

function normalizePhoneForWhatsapp(string $number): string
{
    $number = preg_replace('/[^0-9]/', '', $number) ?? '';
    if ($number === '') {
        return '';
    }

    return $number[0] === '0' ? '62' . substr($number, 1) : $number;
}

function logout(): void
{
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'] ?? '/',
            $params['domain'] ?? '',
            (bool)($params['secure'] ?? false),
            (bool)($params['httponly'] ?? true)
        );
    }

    session_destroy();
}

if (isLoggedIn()) {
    $lastActivity = (int)($_SESSION['last_activity'] ?? time());

    if (time() - $lastActivity > SESSION_TIMEOUT) {
        logout();
        redirect('index.php?timeout=1');
    }

    $_SESSION['last_activity'] = time();

    if (!isset($_SESSION['last_regenerated'])) {
        $_SESSION['last_regenerated'] = time();
    } elseif (time() - (int)$_SESSION['last_regenerated'] > 900) {
        session_regenerate_id(true);
        $_SESSION['last_regenerated'] = time();
    }
}

$errors = [];
$success = (string)($_GET['success'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'logout') {
    requireLogin();
    verifyCsrf();
    logout();
    redirect('index.php?logout=1');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    verifyCsrf();

    if (isLoggedIn()) {
        redirect($_SESSION['role'] === 'bk' ? 'index.php?page=bk' : 'index.php?page=siswa');
    }

    if (tooManyLoginAttempts()) {
        $errors[] = 'Terlalu banyak percobaan login. Tunggu beberapa menit lalu coba lagi.';
    } else {
        $username = trim((string)($_POST['username'] ?? ''));
        $password = (string)($_POST['password'] ?? '');

        // Username boleh 2 karakter agar akun "bk" dari database dapat login.
        if (!preg_match('/^[A-Za-z0-9._-]{2,30}$/', $username)) {
            $errors[] = 'Username tidak valid.';
        }

        if (valueLength($password) < 8 || valueLength($password) > 128) {
            $errors[] = 'Password tidak valid.';
        }

        if (!$errors) {
            $user = null;

            $stmt = mysqli_prepare(
                $conn,
                'SELECT id, username, password_hash, role, nama, kelas, no_wa FROM tb_user WHERE username = ? AND is_active = 1 LIMIT 1'
            );

            if ($stmt) {
                mysqli_stmt_bind_param($stmt, 's', $username);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_bind_result(
                    $stmt,
                    $userId,
                    $userUsername,
                    $userPasswordHash,
                    $userRole,
                    $userNama,
                    $userKelas,
                    $userNoWa
                );

                if (mysqli_stmt_fetch($stmt)) {
                    $user = [
                        'id' => (int)$userId,
                        'username' => $userUsername,
                        'password_hash' => $userPasswordHash,
                        'role' => $userRole,
                        'nama' => $userNama,
                        'kelas' => $userKelas,
                        'no_wa' => $userNoWa
                    ];
                }

                mysqli_stmt_close($stmt);
            }

            if ($user && password_verify($password, $user['password_hash'])) {
                session_regenerate_id(true);

                $_SESSION['login'] = true;
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['nama'] = $user['nama'];
                $_SESSION['kelas'] = $user['kelas'];
                $_SESSION['no_wa'] = $user['no_wa'];
                $_SESSION['last_activity'] = time();
                $_SESSION['last_regenerated'] = time();
                $_SESSION['login_attempts'] = [];

                redirect($user['role'] === 'bk' ? 'index.php?page=bk' : 'index.php?page=siswa');
            }

            registerFailedLogin();
            $errors[] = 'Username atau password salah.';
            usleep(350000);
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_report') {
    requireRole('siswa');
    verifyCsrf();

    $allowedCategories = [
        'Perundungan',
        'Cyberbullying',
        'Masalah Sosial',
        'Ketidaknyamanan Sekolah',
        'Lainnya'
    ];

    $kategori = trim((string)($_POST['kategori'] ?? ''));
    $lokasi = trim((string)($_POST['lokasi'] ?? ''));
    $tanggal = trim((string)($_POST['tanggal'] ?? ''));
    $isiLaporan = trim((string)($_POST['isi_laporan'] ?? ''));

    if (!in_array($kategori, $allowedCategories, true)) {
        $errors[] = 'Kategori laporan tidak valid.';
    }
    if (valueLength($lokasi) < 2 || valueLength($lokasi) > 150) {
        $errors[] = 'Lokasi harus berisi 2 sampai 150 karakter.';
    }
    if (!validDate($tanggal)) {
        $errors[] = 'Tanggal laporan tidak valid atau tidak boleh melebihi hari ini.';
    }
    if (valueLength($isiLaporan) < 10 || valueLength($isiLaporan) > MAX_REPORT_LENGTH) {
        $errors[] = 'Isi laporan harus berisi 10 sampai 5000 karakter.';
    }

    if (!$errors) {
        $stmt = mysqli_prepare(
            $conn,
            "INSERT INTO tb_laporan (user_id, kategori, lokasi, tanggal, isi_laporan, status) VALUES (?, ?, ?, ?, ?, 'Menunggu')"
        );

        if ($stmt) {
            $userId = (int)$_SESSION['user_id'];
            mysqli_stmt_bind_param($stmt, 'issss', $userId, $kategori, $lokasi, $tanggal, $isiLaporan);

            if (mysqli_stmt_execute($stmt)) {
                $newId = mysqli_stmt_insert_id($stmt);
                mysqli_stmt_close($stmt);
                redirect('index.php?page=siswa&success=report&kode=' . (int)$newId);
            }

            mysqli_stmt_close($stmt);
        }

        $errors[] = 'Laporan gagal disimpan. Periksa struktur tabel tb_laporan.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'update_status') {
    requireRole('bk');
    verifyCsrf();

    $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
    $status = trim((string)($_POST['status'] ?? ''));
    $allowedStatuses = ['Menunggu', 'Diproses', 'Selesai'];

    if (!$id || $id < 1) {
        $errors[] = 'ID laporan tidak valid.';
    }
    if (!in_array($status, $allowedStatuses, true)) {
        $errors[] = 'Status laporan tidak valid.';
    }

    if (!$errors) {
        $stmt = mysqli_prepare($conn, 'UPDATE tb_laporan SET status = ? WHERE id = ?');
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, 'si', $status, $id);
            $ok = mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
            redirect('index.php?page=bk&success=' . ($ok ? 'updated' : 'failed'));
        }
        $errors[] = 'Status laporan tidak dapat diperbarui.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_report') {
    requireRole('bk');
    verifyCsrf();

    $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
    if (!$id || $id < 1) {
        $errors[] = 'ID laporan tidak valid.';
    }

    if (!$errors) {
        $stmt = mysqli_prepare($conn, 'DELETE FROM tb_laporan WHERE id = ?');
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, 'i', $id);
            $ok = mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);
            redirect('index.php?page=bk&success=' . ($ok ? 'deleted' : 'failed'));
        }
        $errors[] = 'Laporan tidak dapat dihapus.';
    }
}

$isLoggedIn = isLoggedIn();
$page = 'login';

if ($isLoggedIn) {
    $page = $_SESSION['role'] === 'bk' ? 'bk' : 'siswa';

    $requestedPage = (string)($_GET['page'] ?? '');
    if ($_SESSION['role'] === 'bk' && $requestedPage === 'bk') {
        $page = 'bk';
    }
    if ($_SESSION['role'] === 'siswa' && $requestedPage === 'siswa') {
        $page = 'siswa';
    }
}

$studentReports = [];
if ($page === 'siswa' && $isLoggedIn) {
    $stmt = mysqli_prepare(
        $conn,
        'SELECT id, kategori, lokasi, tanggal, isi_laporan, status, created_at FROM tb_laporan WHERE user_id = ? ORDER BY id DESC'
    );

    if ($stmt) {
        $userId = (int)$_SESSION['user_id'];
        mysqli_stmt_bind_param($stmt, 'i', $userId);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result(
            $stmt,
            $reportId,
            $reportKategori,
            $reportLokasi,
            $reportTanggal,
            $reportIsi,
            $reportStatus,
            $reportCreatedAt
        );

        while (mysqli_stmt_fetch($stmt)) {
            $studentReports[] = [
                'id' => $reportId,
                'kategori' => $reportKategori,
                'lokasi' => $reportLokasi,
                'tanggal' => $reportTanggal,
                'isi_laporan' => $reportIsi,
                'status' => $reportStatus,
                'created_at' => $reportCreatedAt
            ];
        }

        mysqli_stmt_close($stmt);
    }
}

$stats = [
    'total' => 0,
    'menunggu' => 0,
    'diproses' => 0,
    'selesai' => 0
];
$allReports = [];

if ($page === 'bk' && $isLoggedIn) {
    $statsResult = mysqli_query(
        $conn,
        "SELECT COUNT(*) AS total,
                COALESCE(SUM(status = 'Menunggu'), 0) AS menunggu,
                COALESCE(SUM(status = 'Diproses'), 0) AS diproses,
                COALESCE(SUM(status = 'Selesai'), 0) AS selesai
         FROM tb_laporan"
    );

    if ($statsResult) {
        $dbStats = mysqli_fetch_assoc($statsResult);
        if ($dbStats) {
            $stats = $dbStats;
        }
    }

    $reportResult = mysqli_query(
        $conn,
        "SELECT l.id, l.kategori, l.lokasi, l.tanggal, l.isi_laporan, l.status,
                l.created_at, l.updated_at, u.nama, u.kelas, u.no_wa
         FROM tb_laporan l
         INNER JOIN tb_user u ON u.id = l.user_id
         ORDER BY l.id DESC"
    );

    if ($reportResult) {
        while ($row = mysqli_fetch_assoc($reportResult)) {
            $allReports[] = $row;
        }
    }
}

$csrf = csrfToken();
?>
<!DOCTYPE html>
<html lang="id" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#16a34a">
    <title>RuangAman</title>
    <style nonce="<?= e($cspNonce) ?>">
        :root{--bg:#f3f7f4;--surface:#fff;--surface-2:#f8fbf9;--text:#17211b;--muted:#66736b;--border:#dfe8e1;--green:#16a34a;--green-dark:#15803d;--green-soft:#e9f8ee;--danger:#dc2626;--danger-soft:#fef2f2;--warning:#b7791f;--warning-soft:#fff7df;--blue:#2563eb;--blue-soft:#eff6ff;--shadow:0 20px 50px rgba(29,61,40,.08);--radius:20px}
        html[data-theme="dark"]{--bg:#0d1510;--surface:#142019;--surface-2:#19271f;--text:#eff8f1;--muted:#a6b7ab;--border:#2a3a30;--green:#4ade80;--green-dark:#22c55e;--green-soft:#12351f;--danger:#f87171;--danger-soft:#351718;--warning:#f2c15f;--warning-soft:#382f17;--blue:#60a5fa;--blue-soft:#172942;--shadow:0 20px 50px rgba(0,0,0,.28)}
        *{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth}body{min-height:100vh;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(34,197,94,.08),transparent 28%),var(--bg);color:var(--text)}a{color:inherit;text-decoration:none}button,input,textarea,select{font:inherit}button{cursor:pointer}
        .topbar{position:sticky;top:0;z-index:20;background:rgba(255,255,255,.92);border-bottom:1px solid var(--border);backdrop-filter:blur(14px)}html[data-theme="dark"] .topbar{background:rgba(20,32,25,.92)}.topbar-inner,.container{width:min(1180px,92%);margin:auto}.topbar-inner{min-height:74px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:12px;font-weight:800}.brand-mark{width:40px;height:40px;border-radius:13px;display:grid;place-items:center;background:var(--green-soft);color:var(--green-dark);border:1px solid rgba(22,163,74,.18);font-size:18px}.brand small{display:block;color:var(--muted);font-size:11px;margin-top:3px;font-weight:600}.top-actions{display:flex;align-items:center;gap:8px}.icon-button,.ghost-button{border:1px solid var(--border);background:var(--surface);color:var(--text);min-height:40px;border-radius:11px;padding:0 13px}.container{max-width:1180px}.main{padding:36px 0 50px}.hero{background:linear-gradient(135deg,var(--surface),var(--green-soft));border:1px solid var(--border);border-radius:28px;padding:34px;box-shadow:var(--shadow);margin-bottom:26px}.eyebrow{display:inline-flex;align-items:center;gap:7px;color:var(--green-dark);background:var(--surface);border:1px solid var(--border);padding:7px 10px;border-radius:999px;font-weight:800;font-size:12px;margin-bottom:16px}.hero h1{max-width:720px;font-size:clamp(30px,5vw,52px);line-height:1.02;letter-spacing:-1.5px;margin-bottom:14px}.hero p,.section-subtitle{color:var(--muted);line-height:1.7}.hero p{max-width:720px;font-size:15px}.layout-2{display:grid;grid-template-columns:1.15fr .85fr;gap:22px;align-items:start}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}.card-head{padding:23px 24px 0}.card-body{padding:24px}.section-title{font-size:23px;letter-spacing:-.5px}.section-subtitle{margin-top:6px;font-size:14px}.privacy-note{padding:14px 15px;margin-bottom:20px;border-radius:14px;background:var(--green-soft);border:1px solid rgba(22,163,74,.16);line-height:1.6;font-size:13px}.privacy-note b{color:var(--green-dark)}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:17px}.field{display:flex;flex-direction:column;gap:7px}.field.full{grid-column:1/-1}.field label{font-weight:800;font-size:13px}input,select,textarea{width:100%;border:1px solid var(--border);background:var(--surface);color:var(--text);padding:12px 13px;border-radius:12px;outline:none}input:focus,select:focus,textarea:focus{border-color:var(--green);box-shadow:0 0 0 4px rgba(34,197,94,.11)}textarea{min-height:160px;resize:vertical;line-height:1.6}.input-readonly{background:var(--surface-2);color:var(--muted)}.form-footer{margin-top:20px;display:flex;align-items:center;justify-content:space-between;gap:14px}.small-muted,.notice{color:var(--muted);font-size:12px;line-height:1.5}.btn{border:0;border-radius:12px;padding:12px 17px;font-weight:800}.btn-primary{background:var(--green);color:#fff}.btn-secondary{background:var(--surface-2);color:var(--text);border:1px solid var(--border)}.btn-danger{background:var(--danger-soft);color:var(--danger)}.btn-wa{background:var(--green-soft);color:var(--green-dark)}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:24px}.stat{padding:20px}.stat small{color:var(--muted);font-weight:700}.stat h3{font-size:31px;margin-top:8px}.stat.accent{background:linear-gradient(145deg,var(--surface),var(--green-soft))}.report-list{display:flex;flex-direction:column;gap:16px}.report-card{padding:21px;border:1px solid var(--border);background:var(--surface);border-radius:18px}.report-top{display:flex;justify-content:space-between;align-items:center;gap:15px;margin-bottom:15px}.report-code{color:var(--muted);font-weight:800;font-size:13px}.badge{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:800}.badge-menunggu{color:var(--warning);background:var(--warning-soft)}.badge-diproses{color:var(--blue);background:var(--blue-soft)}.badge-selesai{color:var(--green-dark);background:var(--green-soft)}.report-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.info{background:var(--surface-2);border:1px solid var(--border);padding:11px 12px;border-radius:11px}.info small{color:var(--muted);display:block;margin-bottom:4px;font-size:11px;font-weight:700}.info strong{font-size:13px}.description{background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:14px;margin-top:12px;line-height:1.7;overflow-wrap:anywhere;font-size:14px}.report-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:14px}.status-form{display:flex;align-items:center;gap:8px}.status-form select{width:155px;padding:10px 11px}.empty{text-align:center;padding:50px 20px;border:1px dashed var(--border);border-radius:18px;background:var(--surface);color:var(--muted)}.success,.error{border-radius:14px;padding:15px 16px;margin-bottom:20px;line-height:1.6;font-size:13px}.success{color:var(--green-dark);background:var(--green-soft);border:1px solid rgba(22,163,74,.16)}.error{color:var(--danger);background:var(--danger-soft);border:1px solid rgba(220,38,38,.16)}.login-shell{min-height:calc(100vh - 74px);display:grid;place-items:center;padding:40px 0}.login-layout{width:min(980px,92%);display:grid;grid-template-columns:1fr .85fr;gap:22px}.login-brand-panel,.login-card{border-radius:26px;border:1px solid var(--border);background:var(--surface);box-shadow:var(--shadow)}.login-brand-panel{padding:42px;background:linear-gradient(150deg,#14532d,#166534 55%,#15803d);color:#fff;min-height:480px;display:flex;flex-direction:column;justify-content:space-between}.login-brand-panel .brand-mark{background:rgba(255,255,255,.13);color:#fff;border-color:rgba(255,255,255,.18)}.login-brand-panel h1{font-size:clamp(38px,6vw,60px);line-height:.95;letter-spacing:-2px;max-width:500px;margin:35px 0 16px}.login-brand-panel p{max-width:500px;color:rgba(255,255,255,.78);line-height:1.75}.trust-list{display:grid;gap:9px;margin-top:28px}.trust-item{display:flex;align-items:center;gap:9px;color:var(--text);font-size:13px}.login-brand-panel .trust-item{color:rgba(255,255,255,.88)}.trust-dot{width:8px;height:8px;background:#86efac;border-radius:50%;flex:0 0 auto}.login-card{padding:32px;align-self:center}.login-card h2{font-size:28px;margin-bottom:7px}.login-card .subtitle{color:var(--muted);line-height:1.6;font-size:14px;margin-bottom:24px}.login-form{display:grid;gap:15px}.notice{margin-top:18px;text-align:center}.profile-strip{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px}.profile-name{font-size:14px;font-weight:800}.profile-name span{color:var(--muted);font-weight:500}.footer{text-align:center;color:var(--muted);font-size:11px;padding:25px 0 34px}
        @media(max-width:900px){.layout-2,.login-layout{grid-template-columns:1fr}.login-brand-panel{min-height:auto}.stats{grid-template-columns:1fr 1fr}}@media(max-width:650px){.topbar-inner{min-height:68px}.container{width:94%}.main{padding-top:22px}.hero,.login-brand-panel,.login-card{padding:24px}.form-grid,.report-grid{grid-template-columns:1fr}.field.full{grid-column:auto}.form-footer,.profile-strip,.report-top{align-items:flex-start;flex-direction:column}.top-actions .ghost-button{display:none}.status-form{width:100%}.status-form select{flex:1;width:auto}}
    </style>
</head>
<body>
<header class="topbar">
    <div class="topbar-inner">
        <a class="brand" href="<?= $isLoggedIn ? ($page === 'bk' ? 'index.php?page=bk' : 'index.php?page=siswa') : 'index.php' ?>">
            <div class="brand-mark">✓</div>
            <div><strong>RuangAman</strong><small>Komunikasi privat siswa &amp; BK</small></div>
        </a>
        <div class="top-actions">
            <?php if ($isLoggedIn): ?>
                <div class="profile-name"><?= e($_SESSION['nama']) ?> <span>· <?= e($_SESSION['role'] === 'bk' ? 'BK' : $_SESSION['kelas']) ?></span></div>
                <button type="button" class="icon-button" id="themeToggle" aria-label="Ganti tema">☾</button>
                <form method="POST">
                    <input type="hidden" name="action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                    <button type="submit" class="ghost-button">Keluar</button>
                </form>
            <?php else: ?>
                <button type="button" class="icon-button" id="themeToggle" aria-label="Ganti tema">☾</button>
            <?php endif; ?>
        </div>
    </div>
</header>

<?php if ($page === 'login'): ?>
<main class="login-shell">
    <div class="login-layout">
        <section class="login-brand-panel">
            <div>
                <div class="brand">
                    <div class="brand-mark">✓</div>
                    <div><strong>RUANGAMAN</strong><small style="color:rgba(255,255,255,.6)">School reporting channel</small></div>
                </div>
                <h1>Sampaikan.<br>Dicatat.<br>Ditindaklanjuti.</h1>
                <p>Kanal web khusus untuk membantu siswa menyampaikan masalah kepada BK tanpa harus memulai laporan dari chat WhatsApp pribadi.</p>
                <div class="trust-list">
                    <div class="trust-item"><span class="trust-dot"></span>Laporan tersimpan terstruktur</div>
                    <div class="trust-item"><span class="trust-dot"></span>Akses dibatasi berdasarkan akun</div>
                    <div class="trust-item"><span class="trust-dot"></span>Tindak lanjut dapat dilakukan melalui WhatsApp</div>
                </div>
            </div>
            <div style="font-size:11px;color:rgba(255,255,255,.58)">Prototype pembelajaran CRUD sekolah</div>
        </section>

        <section class="login-card">
            <h2>Masuk</h2>
            <p class="subtitle">Gunakan akun yang diberikan sekolah untuk membuka ruang yang sesuai.</p>

            <?php if (isset($_GET['logout'])): ?><div class="success">Kamu sudah keluar dari akun.</div><?php endif; ?>
            <?php if (isset($_GET['timeout'])): ?><div class="success">Sesi berakhir karena tidak ada aktivitas selama 30 menit.</div><?php endif; ?>

            <?php if ($errors): ?>
                <div class="error">
                    <?php foreach ($errors as $error): ?><div><?= e($error) ?></div><?php endforeach; ?>
                </div>
            <?php endif; ?>

            <form method="POST" class="login-form" autocomplete="off">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                <div class="field"><label for="username">Username</label><input id="username" name="username" type="text" maxlength="30" required autocomplete="username" placeholder="Masukkan username"></div>
                <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" maxlength="128" required autocomplete="current-password" placeholder="Masukkan password"></div>
                <button class="btn btn-primary" type="submit">Masuk ke RuangAman</button>
            </form>
            <div class="notice">Untuk laporan yang kamu kirim, jangan tuliskan password, OTP, atau data rahasia akun lain.</div>
        </section>
    </div>
</main>

<?php elseif ($page === 'siswa'): ?>
<main class="main">
    <div class="container">
        <div class="profile-strip">
            <div><div class="section-title">Halo, <?= e($_SESSION['nama']) ?></div><div class="section-subtitle">Sampaikan sesuatu yang ingin kamu laporkan kepada BK.</div></div>
        </div>

        <?php if ($success === 'report'): ?>
            <div class="success">Laporan berhasil disimpan. Nomor laporan kamu adalah <strong>#RA-<?= str_pad((int)($_GET['kode'] ?? 0),4,'0',STR_PAD_LEFT) ?></strong>. BK dapat melihat laporan tersebut dari dashboard.</div>
        <?php endif; ?>
        <?php if ($errors): ?><div class="error"><?php foreach ($errors as $error): ?><div><?= e($error) ?></div><?php endforeach; ?></div><?php endif; ?>

        <div class="layout-2">
            <section class="card">
                <div class="card-head"><h2 class="section-title">Buat laporan</h2><p class="section-subtitle">Isi seperlunya. Laporan akan masuk ke dashboard BK dan tidak ditampilkan kepada siswa lain.</p></div>
                <div class="card-body">
                    <div class="privacy-note"><b>Privat, bukan anonim.</b> Identitas akunmu digunakan BK bila diperlukan untuk tindak lanjut. Gunakan data dummy saat mendemokan sistem di kelas.</div>
                    <form method="POST">
                        <input type="hidden" name="action" value="create_report">
                        <input type="hidden" name="csrf_token" value="<?= e($csrf) ?>">
                        <div class="form-grid">
                            <div class="field"><label for="kategori">Kategori masalah</label><select id="kategori" name="kategori" required><option value="">Pilih kategori</option><option>Perundungan</option><option>Cyberbullying</option><option>Masalah Sosial</option><option>Ketidaknyamanan Sekolah</option><option>Lainnya</option></select></div>
                            <div class="field"><label for="tanggal">Tanggal kejadian</label><input id="tanggal" name="tanggal" type="date" value="<?= e(date('Y-m-d')) ?>" max="<?= e(date('Y-m-d')) ?>" required></div>
                            <div class="field full"><label for="lokasi">Lokasi kejadian</label><input id="lokasi" name="lokasi" type="text" maxlength="150" required placeholder="Contoh: Koridor Gedung B"></div>
                            <div class="field"><label>Nama</label><input class="input-readonly" type="text" value="<?= e($_SESSION['nama']) ?>" readonly></div>
                            <div class="field"><label>Kelas</label><input class="input-readonly" type="text" value="<?= e($_SESSION['kelas']) ?>" readonly></div>
                            <div class="field full"><label for="isi_laporan">Ceritakan apa yang terjadi</label><textarea id="isi_laporan" name="isi_laporan" maxlength="5000" required placeholder="Tuliskan apa yang terjadi dengan bahasa yang jelas dan seperlunya."></textarea></div>
                        </div>
                        <div class="form-footer"><div class="small-muted">Maksimal 5000 karakter. Laporan akan ditinjau oleh pihak BK.</div><button class="btn btn-primary" type="submit">Kirim laporan</button></div>
                    </form>
                </div>
            </section>

            <aside class="card">
                <div class="card-head"><h2 class="section-title">Alur laporan</h2><p class="section-subtitle">Status dibuat sederhana agar proses mudah dipahami.</p></div>
                <div class="card-body">
                    <div class="trust-list">
                        <div class="trust-item"><span class="trust-dot"></span>Menunggu: laporan sudah masuk</div>
                        <div class="trust-item"><span class="trust-dot"></span>Diproses: BK sedang menindaklanjuti</div>
                        <div class="trust-item"><span class="trust-dot"></span>Selesai: proses penanganan dinyatakan selesai</div>
                    </div>
                    <div class="privacy-note" style="margin-top:22px">Untuk keadaan yang membutuhkan bantuan langsung, tetap hubungi guru, BK, wali kelas, atau orang dewasa tepercaya di sekolah. Web ini adalah kanal pelaporan, bukan pengganti penanganan langsung.</div>
                </div>
            </aside>
        </div>

        <section style="margin-top:28px">
            <div style="margin-bottom:14px"><h2 class="section-title">Laporan saya</h2><p class="section-subtitle">Hanya laporan yang dibuat oleh akun ini yang ditampilkan.</p></div>
            <div class="report-list">
                <?php if ($studentReports): foreach ($studentReports as $report):
                    $badgeClass = $report['status'] === 'Diproses' ? 'badge-diproses' : ($report['status'] === 'Selesai' ? 'badge-selesai' : 'badge-menunggu');
                ?>
                    <article class="report-card">
                        <div class="report-top"><div class="report-code">#RA-<?= str_pad((int)$report['id'],4,'0',STR_PAD_LEFT) ?> · <?= e(formatDateTimeId($report['created_at'])) ?></div><span class="badge <?= e($badgeClass) ?>">● <?= e($report['status']) ?></span></div>
                        <div class="report-grid"><div class="info"><small>Kategori</small><strong><?= e($report['kategori']) ?></strong></div><div class="info"><small>Lokasi</small><strong><?= e($report['lokasi']) ?></strong></div><div class="info"><small>Tanggal kejadian</small><strong><?= e(formatDateId($report['tanggal'])) ?></strong></div></div>
                        <div class="description"><?= nl2br(e($report['isi_laporan'])) ?></div>
                    </article>
                <?php endforeach; else: ?>
                    <div class="empty"><strong>Belum ada laporan.</strong><div style="margin-top:6px">Laporan yang kamu kirim akan muncul di sini.</div></div>
                <?php endif; ?>
            </div>
        </section>
    </div>
</main>

<?php else: ?>
<main class="main">
    <div class="container">
        <div class="hero"><span class="eyebrow">Dashboard BK</span><h1>Semua laporan di satu tempat.</h1><p>Laporan siswa tidak perlu menumpuk di chat pribadi. BK dapat memeriksa data, memperbarui status, dan menghubungi pelapor ketika waktu penanganan tersedia.</p></div>

        <?php if ($success === 'updated'): ?><div class="success">Status laporan berhasil diperbarui.</div><?php endif; ?>
        <?php if ($success === 'deleted'): ?><div class="success">Laporan berhasil dihapus dari prototype.</div><?php endif; ?>
        <?php if ($success === 'failed'): ?><div class="error">Perubahan data gagal diproses.</div><?php endif; ?>
        <?php if ($errors): ?><div class="error"><?php foreach ($errors as $error): ?><div><?= e($error) ?></div><?php endforeach; ?></div><?php endif; ?>

        <section class="stats">
            <div class="card stat accent"><small>Total laporan</small><h3><?= (int)$stats['total'] ?></h3></div>
            <div class="card stat"><small>Menunggu</small><h3><?= (int)$stats['menunggu'] ?></h3></div>
            <div class="card stat"><small>Diproses</small><h3><?= (int)$stats['diproses'] ?></h3></div>
            <div class="card stat"><small>Selesai</small><h3><?= (int)$stats['selesai'] ?></h3></div>
        </section>

        <section>
            <div style="margin-bottom:14px"><h2 class="section-title">Laporan masuk</h2><p class="section-subtitle">Data di bawah hanya dapat dilihat oleh akun BK.</p></div>
            <div class="report-list">
                <?php if ($allReports): foreach ($allReports as $report):
                    $badgeClass = $report['status'] === 'Diproses' ? 'badge-diproses' : ($report['status'] === 'Selesai' ? 'badge-selesai' : 'badge-menunggu');
                    $waNumber = normalizePhoneForWhatsapp((string)$report['no_wa']);
                    $message = 'Halo ' . $report['nama'] . ', saya dari BK. Saya ingin menindaklanjuti laporan #RA-' . str_pad((int)$report['id'],4,'0',STR_PAD_LEFT) . '.';
                    $waUrl = 'https://wa.me/' . rawurlencode($waNumber) . '?text=' . rawurlencode($message);
                ?>
                    <article class="report-card">
                        <div class="report-top"><div class="report-code">#RA-<?= str_pad((int)$report['id'],4,'0',STR_PAD_LEFT) ?> · masuk <?= e(formatDateTimeId($report['created_at'])) ?></div><span class="badge <?= e($badgeClass) ?>">● <?= e($report['status']) ?></span></div>
                        <div class="report-grid">
                            <div class="info"><small>Pelapor</small><strong><?= e($report['nama']) ?></strong></div>
                            <div class="info"><small>Kelas</small><strong><?= e($report['kelas']) ?></strong></div>
                            <div class="info"><small>Kategori</small><strong><?= e($report['kategori']) ?></strong></div>
                            <div class="info"><small>Lokasi</small><strong><?= e($report['lokasi']) ?></strong></div>
                            <div class="info"><small>Tanggal kejadian</small><strong><?= e(formatDateId($report['tanggal'])) ?></strong></div>
                            <div class="info"><small>WhatsApp</small><strong><?= e($report['no_wa']) ?></strong></div>
                        </div>
                        <div class="description"><?= nl2br(e($report['isi_laporan'])) ?></div>
                        <div class="report-actions">
                            <form method="POST" class="status-form">
                                <input type="hidden" name="action" value="update_status"><input type="hidden" name="csrf_token" value="<?= e($csrf) ?>"><input type="hidden" name="id" value="<?= (int)$report['id'] ?>">
                                <select name="status" aria-label="Status laporan"><option value="Menunggu"<?= $report['status'] === 'Menunggu' ? ' selected' : '' ?>>Menunggu</option><option value="Diproses"<?= $report['status'] === 'Diproses' ? ' selected' : '' ?>>Diproses</option><option value="Selesai"<?= $report['status'] === 'Selesai' ? ' selected' : '' ?>>Selesai</option></select>
                                <button class="btn btn-secondary" type="submit">Update status</button>
                            </form>
                            <?php if ($waNumber !== ''): ?><a class="btn btn-wa" href="<?= e($waUrl) ?>" target="_blank" rel="noopener noreferrer">Hubungi via WhatsApp</a><?php endif; ?>
                            <form method="POST" data-confirm-delete>
                                <input type="hidden" name="action" value="delete_report"><input type="hidden" name="csrf_token" value="<?= e($csrf) ?>"><input type="hidden" name="id" value="<?= (int)$report['id'] ?>">
                                <button class="btn btn-danger" type="submit">Hapus</button>
                            </form>
                        </div>
                    </article>
                <?php endforeach; else: ?>
                    <div class="empty"><strong>Belum ada laporan masuk.</strong><div style="margin-top:6px">Laporan siswa akan muncul di sini setelah dikirim.</div></div>
                <?php endif; ?>
            </div>
        </section>
    </div>
</main>
<?php endif; ?>

<div class="container"><div class="footer">RuangAman · Prototype CRUD sekolah · Jangan gunakan data siswa asli untuk demo kelas</div></div>

<script nonce="<?= e($cspNonce) ?>">
(function(){
    const html=document.documentElement;
    const button=document.getElementById('themeToggle');
    const saved=localStorage.getItem('ruangaman-theme');
    if(saved==='dark'||saved==='light') html.setAttribute('data-theme',saved);
    function update(){if(!button)return;const dark=html.getAttribute('data-theme')==='dark';button.textContent=dark?'☀':'☾';button.setAttribute('aria-label',dark?'Gunakan tema terang':'Gunakan tema gelap');}
    update();
    if(button)button.addEventListener('click',function(){const next=html.getAttribute('data-theme')==='dark'?'light':'dark';html.setAttribute('data-theme',next);localStorage.setItem('ruangaman-theme',next);update();});
    document.querySelectorAll('[data-confirm-delete]').forEach(function(form){form.addEventListener('submit',function(event){if(!window.confirm('Hapus laporan ini dari prototype? Tindakan ini tidak dapat dibatalkan.'))event.preventDefault();});});
})();
</script>
</body>
</html>
