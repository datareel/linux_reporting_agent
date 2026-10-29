<?php
// upload.php
// Accepts a report only from an approved agent, signed with the key of the
// certificate it registered through register.php. The report is always
// saved as <hostname>_linux_report_agent.txt for the signing host, so
// one agent cannot overwrite another host's report.
//
// Request fields: hostname, timestamp, nonce, signature (base64 RSA SHA-256
// over "upload\n<hostname>\n<timestamp>\n<nonce>\n<sha256 hex of report>",
// followed by a "\n<field> <sha256 hex>" line for each HTML report sent),
// the report file as uploadedFile and, after a new scan, the OpenSCAP
// HTML reports as scapReport and complianceReport.

require_once __DIR__ . '/lra_lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    lra_reply(405, 'error', 'POST required');
}

$cfg = lra_config();
$hostname = strtolower(lra_post('hostname'));
$timestamp = lra_post('timestamp');
$nonce = lra_post('nonce');
$signature = lra_post('signature');

if (!lra_valid_hostname($hostname)) {
    lra_reply(400, 'error', 'Invalid hostname');
}
if (!lra_valid_nonce($nonce)) {
    lra_reply(400, 'error', 'Invalid nonce');
}
if (!lra_check_timestamp($timestamp)) {
    lra_reply(403, 'bad_timestamp', 'Agent clock differs too much from the server clock');
}

$record = lra_load_agent($hostname);
if ($record === null) {
    lra_reply(403, 'not_registered', "Host $hostname is not registered");
}
if ($record['status'] !== 'approved') {
    lra_reply(403, $record['status'], "Host $hostname is " . $record['status']);
}

if (!isset($_FILES['uploadedFile']) || $_FILES['uploadedFile']['error'] !== UPLOAD_ERR_OK) {
    $code = isset($_FILES['uploadedFile']) ? $_FILES['uploadedFile']['error'] : 'missing';
    lra_reply(400, 'error', "File upload failed, error code $code");
}
if ($_FILES['uploadedFile']['size'] > (int)$cfg['upload']['max_upload_bytes']) {
    lra_reply(413, 'error', 'Report is too large');
}
$report = file_get_contents($_FILES['uploadedFile']['tmp_name']);
if ($report === false) {
    lra_reply(500, 'error', 'Could not read the uploaded file');
}

// OpenSCAP HTML reports, in the order the agent signs them
$html = array();
foreach (array('scapReport' => 'scap', 'complianceReport' => 'compliance') as $field => $kind) {
    if (!isset($_FILES[$field])) {
        continue;
    }
    if ($_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        lra_reply(400, 'error', "$field upload failed, error code " . $_FILES[$field]['error']);
    }
    if ($_FILES[$field]['size'] > (int)$cfg['upload']['max_html_bytes']) {
        lra_reply(413, 'error', "$field is too large");
    }
    $data = file_get_contents($_FILES[$field]['tmp_name']);
    if ($data === false) {
        lra_reply(500, 'error', "Could not read $field");
    }
    $html[] = array('field' => $field, 'kind' => $kind, 'data' => $data);
}

$signed = "upload\n$hostname\n$timestamp\n$nonce\n" . hash('sha256', $report);
foreach ($html as $h) {
    $signed .= "\n" . $h['field'] . ' ' . hash('sha256', $h['data']);
}
if (!lra_verify_signature($record['cert_pem'], $signed, $signature)) {
    lra_reply(403, 'bad_signature', 'Signature check failed');
}
if (!lra_use_nonce($hostname, $nonce)) {
    lra_reply(403, 'replay', 'Request was already used');
}

$reports_dir = $cfg['paths']['reports_dir'];
if (!lra_ensure_dir($reports_dir)) {
    lra_reply(500, 'error', 'Reports directory is missing');
}
if (!lra_write_atomic(lra_report_path($hostname), $report, 0644)) {
    lra_reply(500, 'error', 'Could not save the report');
}
foreach ($html as $h) {
    if (!lra_write_atomic(lra_html_path($hostname, $h['kind']), $h['data'], 0644)) {
        lra_reply(500, 'error', 'Could not save the ' . $h['field']);
    }
}

$record['last_seen'] = gmdate('Y-m-d H:i:s') . ' UTC';
$record['last_addr'] = lra_remote_addr();
lra_save_agent($record);

lra_reply(200, 'ok', "Report for $hostname saved" . (count($html) ? ' with ' . count($html) . ' scan report(s)' : ''));
?>
