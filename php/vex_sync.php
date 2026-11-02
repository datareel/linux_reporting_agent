<?php
// vex_sync.php
// Builds the RHEL vulnerability index the Linux agents check their
// packages against (agent [scan] source=csaf), from Red Hat's CSAF VEX
// files: https://security.access.redhat.com/data/csaf/v2/vex/
//
// Red Hat publishes no OVAL feed for RHEL 10, only CSAF/VEX: one JSON
// file per CVE, 74,000 files, 400 MB compressed. Each agent downloading
// that would be too much, so this script runs once on the report server
// (cron, daily) and writes a small index per RHEL release, served to
// the agents by vex_index.php:
//
//   F <cve> <severity> <package> <major> <minor> <fixed epoch:version-release> <RHSA>
//   U <cve> <severity> <source package> <major> <state>
//
// F lines are fixed packages (installed older than this is vulnerable),
// U lines are packages Red Hat lists as affected with no fix yet
// (state: Affected, Fix deferred, Will not fix, Out of support scope).
//
// Usage: php vex_sync.php [--releases 10] [--full] [--dry-run]
//   --releases  RHEL major releases to index, comma separated, default 10
//   --full      Start again from Red Hat's latest full archive
//   --dry-run   Show what would be downloaded, change nothing
//
// The first run downloads the full archive (csaf_vex_<date>.tar.zst,
// needs zstd) and reads it as a stream, so it never unpacks to disk.
// Later runs fetch only the CVE files changes.csv lists as newer. The
// files live in [paths] data_dir/vex/ of server.ini.

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/lra_lib.php';

const VEX_BASE = 'https://security.access.redhat.com/data/csaf/v2/vex/';

$opts = getopt('', array('releases:', 'full', 'dry-run', 'help'));
if (isset($opts['help'])) {
    echo preg_replace('/^\/\/ ?/m', '', implode("\n", array_slice(explode("\n", file_get_contents(__FILE__)), 1, 32))), "\n";
    exit(0);
}
$releases = array();
foreach (explode(',', isset($opts['releases']) ? $opts['releases'] : '10') as $r) {
    if (ctype_digit(trim($r))) {
        $releases[] = (int)trim($r);
    }
}
if (count($releases) == 0) {
    fwrite(STDERR, "ERROR - --releases needs RHEL major numbers, for example 10 or 9,10\n");
    exit(1);
}
$dry = isset($opts['dry-run']);
$cfg = lra_config();
$dir = rtrim($cfg['paths']['data_dir'], '/') . '/vex';
$rec_dir = "$dir/records";
$state_file = "$dir/state.json";
if (!$dry && (!lra_ensure_dir($rec_dir))) {
    fwrite(STDERR, "ERROR - Cannot create $rec_dir\n");
    exit(1);
}
$state = is_file($state_file) ? json_decode(file_get_contents($state_file), true) : null;
if (!is_array($state) || isset($opts['full']) || !isset($state['releases']) || $state['releases'] != $releases) {
    $state = array('last_change' => '', 'releases' => $releases);
}

function vex_log($msg) {
    echo '[' . date('Y-m-d H:i:s') . "] $msg\n";
}

function vex_fetch($url, $dest = null) {
    $ch = curl_init($url);
    $fp = null;
    if ($dest !== null) {
        $fp = fopen($dest, 'wb');
        curl_setopt($ch, CURLOPT_FILE, $fp);
    }
    else {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    }
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $dest !== null ? 3600 : 120);
    curl_setopt($ch, CURLOPT_USERAGENT, 'DataReelReportAgentLinux-vex_sync');
    $data = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($fp) {
        fclose($fp);
    }
    if ($data === false || $code != 200) {
        return false;
    }
    return $dest !== null ? true : $data;
}

// name-[epoch:]version-release.arch into array(name, epoch:version-release, arch)
function vex_split_nevra($nevra) {
    $dot = strrpos($nevra, '.');
    if ($dot === false) {
        return null;
    }
    $arch = substr($nevra, $dot + 1);
    $nevr = substr($nevra, 0, $dot);
    $d2 = strrpos($nevr, '-');
    if ($d2 === false) {
        return null;
    }
    $d1 = strrpos(substr($nevr, 0, $d2), '-');
    if ($d1 === false) {
        return null;
    }
    $name = substr($nevr, 0, $d1);
    $ver = substr($nevr, $d1 + 1, $d2 - $d1 - 1);
    $rel = substr($nevr, $d2 + 1);
    if (strpos($ver, ':') === false) {
        $ver = '0:' . $ver;
    }
    return array($name, "$ver-$rel", $arch);
}

// Index lines of one VEX file for the releases, '' when none apply
function vex_records($json, $releases) {
    // Most CVEs never mention these releases, skip them before decoding
    $hit = false;
    foreach ($releases as $r) {
        if (strpos($json, "red_hat_enterprise_linux_$r") !== false || preg_match("/[A-Za-z]-$r\\.\\d/", $json)) {
            $hit = true;
        }
    }
    if (!$hit) {
        return '';
    }
    $d = json_decode($json, true);
    if (!is_array($d) || !isset($d['vulnerabilities'])) {
        return '';
    }
    $sev = isset($d['document']['aggregate_severity']['text']) ? $d['document']['aggregate_severity']['text'] : 'Unknown';
    $lines = array();
    foreach ($d['vulnerabilities'] as $v) {
        $cve = isset($v['cve']) ? $v['cve'] : '';
        if (!preg_match('/^CVE-\d{4}-\d+$/', $cve)) {
            continue;
        }
        // Severity of this CVE, from its impact threat when there is one
        $vsev = $sev;
        foreach (isset($v['threats']) ? $v['threats'] : array() as $t) {
            if (isset($t['category']) && $t['category'] === 'impact' && isset($t['details'])) {
                $vsev = $t['details'];
                break;
            }
        }
        $vsev = ucfirst(strtolower(trim($vsev)));
        if (!in_array($vsev, array('Critical', 'Important', 'Moderate', 'Low'))) {
            $vsev = 'Unknown';
        }
        // RHSA and unfixed state for each product id
        $rhsa = array();
        $why = array();
        foreach (isset($v['remediations']) ? $v['remediations'] : array() as $rem) {
            $cat = isset($rem['category']) ? $rem['category'] : '';
            $ids = isset($rem['product_ids']) ? $rem['product_ids'] : array();
            if ($cat === 'vendor_fix' && isset($rem['url']) && preg_match('/(RH[SBE]A-\d{4}:\d+)/', $rem['url'], $m)) {
                foreach ($ids as $id) {
                    $rhsa[$id] = $m[1];
                }
            }
            else if ($cat === 'none_available' || $cat === 'no_fix_planned') {
                $text = isset($rem['details']) ? trim($rem['details']) : '';
                if ($text === '') {
                    $text = $cat === 'no_fix_planned' ? 'Will not fix' : 'Affected';
                }
                foreach ($ids as $id) {
                    $why[$id] = preg_replace('/[\t\r\n]+/', ' ', $text);
                }
            }
        }
        $status = isset($v['product_status']) ? $v['product_status'] : array();
        foreach (isset($status['fixed']) ? $status['fixed'] : array() as $id) {
            // AppStream-10.2.Z:openssl-1:3.5.8-2.el10_2.x86_64
            if (!preg_match('/^[A-Za-z_]+-(\d+)\.(\d+)[^:]*:(.+)$/', $id, $m) || !in_array((int)$m[1], $releases)) {
                continue;
            }
            $p = vex_split_nevra($m[3]);
            if ($p === null || $p[2] === 'src' || preg_match('/-(debuginfo|debugsource)$/', $p[0])) {
                continue;
            }
            $r = isset($rhsa[$id]) ? $rhsa[$id] : '';
            $lines["F\t$cve\t$vsev\t{$p[0]}\t{$m[1]}\t{$m[2]}\t{$p[1]}\t$r"] = 1;
        }
        foreach (isset($status['known_affected']) ? $status['known_affected'] : array() as $id) {
            // red_hat_enterprise_linux_10:edk2-ovmf, or :bootc.src
            if (!preg_match('/^red_hat_enterprise_linux_(\d+):([A-Za-z0-9._+-]+)$/', $id, $m) || !in_array((int)$m[1], $releases)) {
                continue;
            }
            $comp = preg_replace('/\.src$/', '', $m[2]);
            $w = isset($why[$id]) ? $why[$id] : 'Affected';
            $lines["U\t$cve\t$vsev\t$comp\t{$m[1]}\t$w"] = 1;
        }
    }
    return count($lines) ? implode("\n", array_keys($lines)) . "\n" : '';
}

function vex_save_record($rec_dir, $path, $records) {
    // 2026/cve-2026-1234.json -> records/2026/cve-2026-1234.tsv
    if (!preg_match('#^(\d{4})/(cve-\d{4}-\d+)\.json$#', $path, $m)) {
        return;
    }
    $f = "$rec_dir/{$m[1]}/{$m[2]}.tsv";
    if ($records === '') {
        if (is_file($f)) {
            unlink($f);
        }
        return;
    }
    lra_ensure_dir(dirname($f));
    lra_write_atomic($f, $records, 0644);
}

// Reads a tar stream (from zstd -dc) file by file
function vex_read_archive($archive, $rec_dir, $releases) {
    $p = popen('zstd -dc ' . escapeshellarg($archive), 'r');
    if ($p === false) {
        return false;
    }
    $n = 0;
    $kept = 0;
    $longname = null;
    while (!feof($p)) {
        $hdr = stream_get_contents($p, 512);
        if ($hdr === false || strlen($hdr) < 512 || trim($hdr, "\0") === '') {
            break;
        }
        $name = rtrim(substr($hdr, 0, 100), "\0");
        $prefix = rtrim(substr($hdr, 345, 155), "\0");
        if ($prefix !== '') {
            $name = "$prefix/$name";
        }
        $size = octdec(trim(substr($hdr, 124, 12), "\0 "));
        $type = substr($hdr, 156, 1);
        $data = $size > 0 ? stream_get_contents($p, $size) : '';
        $pad = (512 - ($size % 512)) % 512;
        if ($pad) {
            stream_get_contents($p, $pad);
        }
        if ($type === 'L') {
            // GNU long name for the next entry
            $longname = rtrim($data, "\0");
            continue;
        }
        if ($longname !== null) {
            $name = $longname;
            $longname = null;
        }
        if (($type !== '0' && $type !== "\0") || substr($name, -5) !== '.json') {
            continue;
        }
        $name = preg_replace('#^(\./)?#', '', $name);
        $rec = vex_records($data, $releases);
        vex_save_record($rec_dir, $name, $rec);
        $n++;
        if ($rec !== '') {
            $kept++;
        }
        if ($n % 5000 == 0) {
            vex_log("  $n CVE files read, $kept apply");
        }
    }
    pclose($p);
    vex_log("Archive: $n CVE files read, $kept apply to RHEL " . implode(', ', $releases));
    return true;
}

// ------------------------------------------------------------------ main

if ($state['last_change'] === '') {
    $latest = trim((string)vex_fetch(VEX_BASE . 'archive_latest.txt'));
    if (!preg_match('/^csaf_vex_(\d{4}-\d{2}-\d{2})\.tar\.zst$/', $latest, $m)) {
        fwrite(STDERR, "ERROR - Could not read " . VEX_BASE . "archive_latest.txt\n");
        exit(1);
    }
    if ($dry) {
        vex_log("Would download the full archive $latest (about 400 MB) and index it");
        exit(0);
    }
    if (trim(shell_exec('command -v zstd 2> /dev/null')) === '') {
        fwrite(STDERR, "ERROR - The first sync needs zstd (dnf install zstd)\n");
        exit(1);
    }
    $archive = "$dir/$latest";
    if (!is_file($archive)) {
        vex_log("Downloading $latest");
        if (!vex_fetch(VEX_BASE . $latest, "$archive.part") || !rename("$archive.part", $archive)) {
            @unlink("$archive.part");
            fwrite(STDERR, "ERROR - Could not download " . VEX_BASE . "$latest\n");
            exit(1);
        }
    }
    vex_log("Reading $latest");
    if (!vex_read_archive($archive, $rec_dir, $releases)) {
        fwrite(STDERR, "ERROR - Could not read $archive\n");
        exit(1);
    }
    // Changes after the archive date come from changes.csv below. Saved
    // now, so a run that stops later does not read the archive again.
    $state['last_change'] = $m[1] . 'T00:00:00+00:00';
    lra_write_atomic($state_file, json_encode($state) . "\n", 0644);
    unlink($archive);
}

$changes = vex_fetch(VEX_BASE . 'changes.csv');
if ($changes === false) {
    fwrite(STDERR, "ERROR - Could not download " . VEX_BASE . "changes.csv\n");
    exit(1);
}
$todo = array();
foreach (explode("\n", $changes) as $line) {
    if (!preg_match('/^"(\d{4}\/cve-\d{4}-\d+\.json)","([^"]+)"$/', trim($line), $m)) {
        continue;
    }
    // >= so a file with the same time as the last one read is not missed
    if (strcmp($m[2], $state['last_change']) >= 0) {
        $todo[$m[1]] = $m[2];
    }
}
// Files that failed to download last time are tried again
$retry = isset($state['retry']) && is_array($state['retry']) ? $state['retry'] : array();
foreach ($retry as $path) {
    if (preg_match('/^\d{4}\/cve-\d{4}-\d+\.json$/', $path) && !isset($todo[$path])) {
        $todo[$path] = '';
    }
}
// Oldest first, so last_change can move forward batch by batch and a
// run that stops goes on from there next time
asort($todo);
vex_log(count($todo) . " CVE files changed since " . $state['last_change']);
if ($dry) {
    exit(0);
}

// Fetches several files at once, returns path => JSON (false on failure)
function vex_fetch_many($paths) {
    $mh = curl_multi_init();
    $handles = array();
    foreach ($paths as $path) {
        $ch = curl_init(VEX_BASE . $path);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 120);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_USERAGENT, 'DataReelReportAgentLinux-vex_sync');
        curl_multi_add_handle($mh, $ch);
        $handles[$path] = $ch;
    }
    do {
        $st = curl_multi_exec($mh, $running);
        if ($running) {
            curl_multi_select($mh, 1.0);
        }
    } while ($running && $st == CURLM_OK);
    $out = array();
    foreach ($handles as $path => $ch) {
        $ok = curl_getinfo($ch, CURLINFO_RESPONSE_CODE) == 200;
        $out[$path] = $ok ? curl_multi_getcontent($ch) : false;
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);
    return $out;
}

$failed = 0;
$done = 0;
$state['retry'] = array();
foreach (array_chunk(array_keys($todo), 16) as $batch) {
    foreach (vex_fetch_many($batch) as $path => $json) {
        if ($json === false) {
            // Kept on the retry list, so one bad file does not hold back
            // last_change and make every later run read everything again
            $failed++;
            $state['retry'][] = $path;
            continue;
        }
        vex_save_record($rec_dir, $path, vex_records($json, $releases));
    }
    $done += count($batch);
    $t = $todo[end($batch)];
    if ($t !== '' && strcmp($t, $state['last_change']) > 0) {
        $state['last_change'] = $t;
    }
    lra_write_atomic($state_file, json_encode($state) . "\n", 0644);
    if ($done % 800 == 0) {
        vex_log("  $done of " . count($todo) . " changed files read");
    }
}
if ($failed > 0) {
    vex_log("WARNING - $failed CVE files could not be downloaded, they are retried next run");
}

// Deleted CVE files drop out of the index
$del = vex_fetch(VEX_BASE . 'deletions.csv');
if ($del !== false) {
    foreach (explode("\n", $del) as $line) {
        if (preg_match('/^"(\d{4}\/cve-\d{4}-\d+\.json)"/', trim($line), $m)) {
            vex_save_record($rec_dir, $m[1], '');
        }
    }
}

// One gzip index per release
$records = glob("$rec_dir/*/*.tsv") ?: array();
sort($records);
foreach ($releases as $r) {
    $out = "# DataReel Reporting Agent VEX index for RHEL $r\n# generated " . time() . " from " . VEX_BASE . "\n";
    $nf = 0;
    $nu = 0;
    foreach ($records as $f) {
        foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $c = explode("\t", $line);
            if (count($c) >= 5 && (int)$c[4] === $r) {
                $out .= $line . "\n";
                if ($c[0] === 'F') {
                    $nf++;
                }
                else {
                    $nu++;
                }
            }
        }
    }
    $gz = gzencode($out, 9);
    if (!lra_write_atomic("$dir/vex_rhel$r.tsv.gz", $gz, 0644)) {
        fwrite(STDERR, "ERROR - Could not write $dir/vex_rhel$r.tsv.gz\n");
        exit(1);
    }
    vex_log("RHEL $r index: $nf fixed package lines, $nu unfixed, " . round(strlen($gz) / 1024) . " KB");
}
exit($failed > 0 ? 1 : 0);
?>
