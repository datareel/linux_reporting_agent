<?php
// hook_lib.php
// Hook uploads: manifests, storage and the built-in parsers for hook.php
//
// A hook upload is a report from another source (a manual scan, a custom
// application, a backup job) that an agent sends with hook.php. The
// server only takes hook IDs that have a manifest in [hooks]
// manifest_dir, the DRSM plugin folder plugins/uploads:
//
//   <manifest_dir>/<id>/plugin.conf   (or <manifest_dir>/<id>.conf)
//
// KEY=value lines as in every DRSM plugin.conf. hook.php reads FORMAT,
// MAX_BYTES, KEEP_HISTORY and MIN_INTERVAL_SECONDS; DRSM reads the rest.
//
// Payloads are kept per host the data is about (the subject):
//
//   <hooks_dir>/<subject>/<id>/latest.data    the file as sent
//   <hooks_dir>/<subject>/<id>/latest.lines   parsed DRSM lines
//   <hooks_dir>/<subject>/<id>/latest.meta    envelope and receive time
//   <hooks_dir>/<subject>/<id>/history/<etime>.{data,meta}
//
// The parsers never run or include a payload. XML is read without
// network access or entity expansion.

require_once __DIR__ . '/lra_lib.php';

define('LRA_HOOK_FORMATS', 'drsm-lines kv-sections json csv xccdf-results text html');
define('LRA_HOOK_MAX_LINES', 5000);

function lra_hook_config() {
    $cfg = lra_config();
    $defaults = array(
        'enabled' => '1',
        'manifest_dir' => '',
        'dir' => rtrim($cfg['paths']['data_dir'], '/') . '/hooks',
        'max_bytes' => '20000000',
    );
    $ini_path = lra_server_ini_path();
    $ini = is_readable($ini_path) ? parse_ini_file($ini_path, true, INI_SCANNER_RAW) : array();
    $hooks = $defaults;
    if (is_array($ini) && isset($ini['hooks']) && is_array($ini['hooks'])) {
        foreach ($defaults as $key => $value) {
            if (isset($ini['hooks'][$key]) && trim($ini['hooks'][$key]) !== '') {
                $hooks[$key] = trim($ini['hooks'][$key]);
            }
        }
    }
    foreach (array('manifest_dir', 'dir') as $key) {
        $dir = $hooks[$key];
        if ($dir !== '' && $dir[0] !== '/') {
            $hooks[$key] = dirname($ini_path) . '/' . $dir;
        }
    }
    return $hooks;
}

function lra_valid_hook_id($id) {
    return is_string($id) && preg_match('/^[a-z0-9_]{1,32}$/', $id) === 1;
}

// KEY=value file with # comments and "quoted" values, like DRSM's
// lib/drsm_conf.sh. Returns null when the file is missing.
function lra_read_conf($path) {
    if (!is_file($path) || !is_readable($path)) {
        return null;
    }
    $conf = array();
    foreach (file($path, FILE_IGNORE_NEW_LINES) ?: array() as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        if (!preg_match('/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/', $line, $m)) {
            continue;
        }
        $val = trim($m[2]);
        if (strlen($val) >= 2 && ($val[0] === '"' || $val[0] === "'")) {
            $q = $val[0];
            $end = strpos($val, $q, 1);
            $val = $end === false ? substr($val, 1) : substr($val, 1, $end - 1);
        } else {
            $hash = strpos($val, ' #');
            if ($hash !== false) {
                $val = rtrim(substr($val, 0, $hash));
            }
        }
        $conf[$m[1]] = $val;
    }
    return $conf;
}

// The manifest of a hook, or null when the server does not take it
function lra_hook_manifest($id) {
    $hooks = lra_hook_config();
    if (!lra_valid_hook_id($id) || $hooks['manifest_dir'] === '') {
        return null;
    }
    $dir = rtrim($hooks['manifest_dir'], '/');
    $conf = lra_read_conf("$dir/$id/plugin.conf");
    if ($conf === null) {
        $conf = lra_read_conf("$dir/$id.conf");
    }
    if ($conf === null) {
        return null;
    }
    $max = (int)$hooks['max_bytes'];
    if (isset($conf['MAX_BYTES']) && (int)$conf['MAX_BYTES'] > 0 && (int)$conf['MAX_BYTES'] < $max) {
        $max = (int)$conf['MAX_BYTES'];
    }
    $format = isset($conf['FORMAT']) ? strtolower($conf['FORMAT']) : '';
    return array(
        'id' => $id,
        'format' => $format,
        'max_bytes' => $max,
        'keep_history' => isset($conf['KEEP_HISTORY']) && ctype_digit($conf['KEEP_HISTORY']) ? (int)$conf['KEEP_HISTORY'] : 3,
        'min_interval' => isset($conf['MIN_INTERVAL_SECONDS']) && ctype_digit($conf['MIN_INTERVAL_SECONDS']) ? (int)$conf['MIN_INTERVAL_SECONDS'] : 10,
        'conf' => $conf,
    );
}

function lra_hook_dir($subject, $id) {
    $hooks = lra_hook_config();
    return rtrim($hooks['dir'], '/') . '/' . $subject . '/' . $id;
}

// The envelope the agent sends: "KEY: value" lines. Only known keys are
// kept, each one line of printable text.
function lra_hook_parse_envelope($text) {
    $keys = array('HOOK_ID', 'TITLE', 'SUBJECT', 'FORMAT', 'CONTENT_TYPE', 'FILE_NAME', 'COLLECTED',
                  'COLLECTED_ETIME', 'SOURCE', 'AGENT_VERSION', 'SHA256');
    $env = array();
    foreach (preg_split('/\r?\n/', $text) as $line) {
        if (!preg_match('/^([A-Z_]+): ?(.*)$/', $line, $m) || !in_array($m[1], $keys, true)) {
            continue;
        }
        $env[$m[1]] = lra_hook_clean_value($m[2], 200);
    }
    return $env;
}

function lra_hook_clean_value($value, $max) {
    $value = preg_replace('/[\x00-\x1f\x7f]+/', ' ', (string)$value);
    if (strlen($value) > $max) {
        $value = substr($value, 0, $max);
    }
    return trim($value);
}

function lra_hook_format($manifest, $env) {
    $known = explode(' ', LRA_HOOK_FORMATS);
    $format = $manifest['format'];
    if ($format === '' || $format === 'auto') {
        $format = isset($env['FORMAT']) ? strtolower($env['FORMAT']) : '';
    }
    return in_array($format, $known, true) ? $format : 'text';
}

// --------------------------------------------------------------------
// Parsers: payload -> DRSM lines: UPLOAD value|<name>|<value>,
// UPLOAD columns|..., UPLOAD row|..., and from drsm-lines also INFO, WARNING,
// ERROR, UNKNOWN and METRIC lines. DRSM's uploads/<id> plugin applies the
// manifest rules (WARN_IF, CRIT_IF, METRICS) to them.
// --------------------------------------------------------------------

function lra_hook_detail_name($name) {
    $name = strtolower(preg_replace('/[^A-Za-z0-9_.]+/', '_', $name));
    return trim(substr($name, 0, 100), '_.');
}

function lra_hook_detail($name, $value) {
    $name = lra_hook_detail_name($name);
    if ($name === '') {
        return '';
    }
    if (is_bool($value)) {
        $value = $value ? 'true' : 'false';
    } elseif ($value === null) {
        $value = 'null';
    }
    return 'UPLOAD value|' . $name . '|' . lra_hook_clean_value($value, 500) . "\n";
}

function lra_hook_row($kind, $cells) {
    $out = array();
    foreach ($cells as $c) {
        $out[] = str_replace('|', '/', lra_hook_clean_value($c, 300));
    }
    return 'UPLOAD ' . $kind . '|' . implode('|', $out) . "\n";
}

function lra_hook_parse_drsm_lines($data) {
    $out = '';
    $n = 0;
    foreach (preg_split('/\r?\n/', $data) as $line) {
        $line = rtrim($line);
        if (strlen($line) > 1000) {
            $line = substr($line, 0, 1000);
        }
        if (preg_match('/^(INFO|WARNING|ERROR|UNKNOWN) - ./', $line)
            || preg_match('/^METRIC [a-z_][a-z0-9_]*(\{[a-z_]+="?[A-Za-z0-9_.:\/-]*"?(,[a-z_]+="?[A-Za-z0-9_.:\/-]*"?)*\})?=-?[0-9.]+$/', $line)
            || preg_match('/^UPLOAD (columns|row|value)\|/', $line)) {
            $out .= preg_replace('/[\x00-\x1f\x7f]/', ' ', $line) . "\n";
            if (++$n >= LRA_HOOK_MAX_LINES) {
                break;
            }
        } elseif (preg_match('/^DETAIL ([A-Za-z0-9_.]+)=(.*)$/', $line, $m)) {
            // Values, not host facts: a hook never sets the host's Details panel
            $out .= lra_hook_detail($m[1], $m[2]);
            if (++$n >= LRA_HOOK_MAX_LINES) {
                break;
            }
        }
    }
    return $out;
}

// "NAME:" ... "END NAME" sections of name=value lines, as in the agent
// reports: UPLOAD value|<section>.<name>|<value>
function lra_hook_parse_kv_sections($data) {
    $out = '';
    $section = '';
    $n = 0;
    foreach (preg_split('/\r?\n/', $data) as $line) {
        $line = trim($line);
        if ($section === '' && preg_match('/^([A-Z][A-Z0-9 _-]*):$/', $line, $m)) {
            $section = $m[1];
            continue;
        }
        if ($section !== '' && $line === 'END ' . $section) {
            $section = '';
            continue;
        }
        if ($section !== '' && preg_match('/^([A-Za-z0-9_.{}=-]+?)=(.*)$/', $line, $m)) {
            $val = $m[2];
            if (strlen($val) >= 2 && $val[0] === '"') {
                $val = stripcslashes(substr($val, 1, -1));
            }
            $out .= lra_hook_detail(str_replace(' ', '_', $section) . '.' . $m[1], $val);
            if (++$n >= LRA_HOOK_MAX_LINES) {
                break;
            }
        }
    }
    return $out;
}

function lra_hook_flatten($prefix, $value, &$out, &$n) {
    if ($n >= LRA_HOOK_MAX_LINES) {
        return;
    }
    if (is_array($value)) {
        if (count($value) === 0) {
            $out .= lra_hook_detail($prefix, '');
            $n++;
        }
        foreach ($value as $k => $v) {
            lra_hook_flatten($prefix === '' ? (string)$k : "$prefix.$k", $v, $out, $n);
        }
        return;
    }
    $out .= lra_hook_detail($prefix === '' ? 'value' : $prefix, $value);
    $n++;
}

function lra_hook_parse_json($data, &$error) {
    $value = json_decode($data, true, 32);
    if ($value === null && json_last_error() !== JSON_ERROR_NONE) {
        $error = 'JSON: ' . json_last_error_msg();
        return '';
    }
    $out = '';
    $n = 0;
    lra_hook_flatten('', $value, $out, $n);
    return $out;
}

function lra_hook_parse_csv($data) {
    $fp = fopen('php://temp', 'r+');
    fwrite($fp, $data);
    rewind($fp);
    $out = '';
    $rows = 0;
    $header = fgetcsv($fp, 0, ',', '"', '\\');
    if (is_array($header)) {
        if (isset($header[0])) {
            $header[0] = preg_replace('/^\xEF\xBB\xBF/', '', $header[0]);
        }
        $out .= lra_hook_row('columns', $header);
        while (($row = fgetcsv($fp, 0, ',', '"', '\\')) !== false) {
            if ($row === array(null)) {
                continue;
            }
            $rows++;
            if ($rows <= LRA_HOOK_MAX_LINES) {
                $out .= lra_hook_row('row', $row);
            }
        }
    }
    fclose($fp);
    return lra_hook_detail('rows', $rows) . $out;
}

// oscap xccdf eval --results: counts by result, failed rules by
// severity, the score, and a row per failed rule
function lra_hook_parse_xccdf($data, &$error) {
    if (!class_exists('XMLReader')) {
        $error = 'PHP XMLReader is not installed';
        return '';
    }
    $xml = new XMLReader();
    if (!$xml->XML($data, null, LIBXML_NONET | LIBXML_COMPACT)) {
        $error = 'not XML';
        return '';
    }
    $titles = array();
    $results = array();
    $counts = array();
    $fail_sev = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'unknown' => 0);
    $score = '';
    $profile = '';
    $rule_id = '';
    $in_rule_title = false;
    $current = null;
    $prev = libxml_use_internal_errors(true);
    while (@$xml->read()) {
        if ($xml->nodeType === XMLReader::ELEMENT) {
            $name = $xml->localName;
            if ($name === 'Rule') {
                $rule_id = (string)$xml->getAttribute('id');
            } elseif ($name === 'title' && $rule_id !== '' && !isset($titles[$rule_id])) {
                $in_rule_title = true;
            } elseif ($name === 'rule-result') {
                $current = array('id' => (string)$xml->getAttribute('idref'),
                                 'severity' => strtolower((string)$xml->getAttribute('severity')),
                                 'result' => '');
            } elseif ($name === 'result' && $current !== null) {
                $current['result'] = strtolower(trim($xml->readString()));
            } elseif ($name === 'score' && $score === '') {
                $score = trim($xml->readString());
            } elseif ($name === 'profile' && $profile === '' && $xml->getAttribute('idref') !== null) {
                $profile = (string)$xml->getAttribute('idref');
            }
        } elseif ($xml->nodeType === XMLReader::TEXT && $in_rule_title) {
            $titles[$rule_id] = trim($xml->value);
        } elseif ($xml->nodeType === XMLReader::END_ELEMENT) {
            if ($xml->localName === 'title') {
                $in_rule_title = false;
            } elseif ($xml->localName === 'Rule') {
                $rule_id = '';
            } elseif ($xml->localName === 'rule-result' && $current !== null) {
                $r = $current['result'] === '' ? 'unknown' : $current['result'];
                $counts[$r] = isset($counts[$r]) ? $counts[$r] + 1 : 1;
                if ($r === 'fail') {
                    $sev = isset($fail_sev[$current['severity']]) ? $current['severity'] : 'unknown';
                    $fail_sev[$sev]++;
                    $results[] = $current;
                }
                $current = null;
            }
        }
    }
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    $xml->close();
    if (count($counts) === 0) {
        $error = 'no rule-result elements, is this oscap xccdf --results output?';
        return '';
    }
    $out = '';
    foreach (array('pass', 'fail', 'error', 'unknown', 'notapplicable', 'notchecked', 'notselected', 'informational', 'fixed') as $r) {
        $out .= lra_hook_detail($r, isset($counts[$r]) ? $counts[$r] : 0);
    }
    foreach ($fail_sev as $sev => $n) {
        $out .= lra_hook_detail("fail_$sev", $n);
    }
    if ($score !== '' && is_numeric($score)) {
        $out .= lra_hook_detail('score', round((float)$score, 1));
    }
    if ($profile !== '') {
        $out .= lra_hook_detail('profile', $profile);
    }
    $rank = array('critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'unknown' => 4);
    usort($results, function ($a, $b) use ($rank) {
        $ra = isset($rank[$a['severity']]) ? $rank[$a['severity']] : 4;
        $rb = isset($rank[$b['severity']]) ? $rank[$b['severity']] : 4;
        return $ra === $rb ? strcmp($a['id'], $b['id']) : $ra - $rb;
    });
    $out .= lra_hook_row('columns', array('Severity', 'Rule', 'Title'));
    foreach (array_slice($results, 0, 1000) as $r) {
        $short = preg_replace('/^xccdf_org\.ssgproject\.content_rule_/', '', $r['id']);
        $out .= lra_hook_row('row', array($r['severity'], $short, isset($titles[$r['id']]) ? $titles[$r['id']] : ''));
    }
    return $out;
}

// Returns the DRSM lines for a payload; $error says why parsing failed
function lra_hook_parse($format, $data, &$error) {
    $error = '';
    switch ($format) {
        case 'drsm-lines':
            return lra_hook_parse_drsm_lines($data);
        case 'kv-sections':
            return lra_hook_parse_kv_sections($data);
        case 'json':
            return lra_hook_parse_json($data, $error);
        case 'csv':
            return lra_hook_parse_csv($data);
        case 'xccdf-results':
            return lra_hook_parse_xccdf($data, $error);
        case 'text':
            return lra_hook_detail('lines', substr_count($data, "\n") + (substr($data, -1) === "\n" || $data === '' ? 0 : 1));
        default:
            return '';
    }
}

function lra_hook_meta_text($meta) {
    $text = '';
    foreach ($meta as $k => $v) {
        $text .= $k . ': ' . $v . "\n";
    }
    return $text;
}

// Saves a payload, its lines and its meta, after moving the previous
// one to history/
function lra_hook_store($subject, $manifest, $data, $lines, $meta) {
    $dir = lra_hook_dir($subject, $manifest['id']);
    if (!lra_ensure_dir($dir)) {
        return false;
    }
    $keep = $manifest['keep_history'];
    if (is_file("$dir/latest.meta") && $keep > 0 && lra_ensure_dir("$dir/history")) {
        $old = lra_read_meta("$dir/latest.meta");
        $t = isset($old['RECEIVED_ETIME']) && ctype_digit($old['RECEIVED_ETIME']) ? $old['RECEIVED_ETIME'] : (string)filemtime("$dir/latest.meta");
        foreach (array('data', 'meta', 'lines') as $ext) {
            if (is_file("$dir/latest.$ext")) {
                @rename("$dir/latest.$ext", "$dir/history/$t.$ext");
            }
        }
        $files = glob("$dir/history/*.meta") ?: array();
        sort($files);
        while (count($files) > $keep) {
            $f = array_shift($files);
            $base = substr($f, 0, -5);
            foreach (array('data', 'meta', 'lines') as $ext) {
                if (is_file("$base.$ext")) {
                    @unlink("$base.$ext");
                }
            }
        }
    }
    // The meta file goes last: readers take its time as the payload's
    return lra_write_atomic("$dir/latest.data", $data, 0644)
        && lra_write_atomic("$dir/latest.lines", $lines, 0644)
        && lra_write_atomic("$dir/latest.meta", lra_hook_meta_text($meta), 0644);
}

function lra_read_meta($path) {
    $meta = array();
    foreach (@file($path, FILE_IGNORE_NEW_LINES) ?: array() as $line) {
        if (preg_match('/^([A-Z_]+): (.*)$/', $line, $m)) {
            $meta[$m[1]] = $m[2];
        }
    }
    return $meta;
}
?>
