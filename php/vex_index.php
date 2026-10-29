<?php
// vex_index.php
// Serves the RHEL vulnerability index that vex_sync.php builds:
// vex_index.php?rhel=10. Agents with [scan] source=csaf download it
// when it changed (If-Modified-Since). It is Red Hat's public VEX data,
// so no login is needed.

require_once __DIR__ . '/lra_lib.php';

$rhel = isset($_GET['rhel']) && is_string($_GET['rhel']) && ctype_digit($_GET['rhel']) ? (int)$_GET['rhel'] : 0;
$cfg = lra_config();
$f = rtrim($cfg['paths']['data_dir'], '/') . "/vex/vex_rhel$rhel.tsv.gz";
if ($rhel < 8 || $rhel > 99 || !is_file($f)) {
    lra_reply(404, 'error', "No VEX index for RHEL $rhel, run vex_sync.php --releases $rhel on the server");
}
$mtime = filemtime($f);
header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE'])) {
    $since = strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']);
    if ($since !== false && $since >= $mtime) {
        http_response_code(304);
        exit;
    }
}
header('Content-Type: application/gzip');
header('Content-Length: ' . filesize($f));
readfile($f);
?>
