<?php
// hook.php
// Accepts a report from another source (a hook) from an approved agent,
// signed with the key of the certificate it registered through
// register.php. Only hook IDs with a manifest in [hooks] manifest_dir
// are taken (see hook_lib.php). The payload is parsed once here into
// DRSM lines, so DRSM's uploads/<id> plugin only reads plain text.
//
// Request fields: hostname, timestamp, nonce, hookId, subject, signature
// (base64 RSA SHA-256 over "hook\n<hostname>\n<timestamp>\n<nonce>\n
// <hookId>\n<subject>\n<sha256 hex of envelope>\n<sha256 hex of payload>"),
// and the files envelope ("KEY: value" lines) and payload.
//
// The subject is the host the data is about. For now it must be the
// signing host.

require_once __DIR__ . '/hook_lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    lra_reply(405, 'error', 'POST required');
}

$hooks = lra_hook_config();
if ($hooks['enabled'] !== '1') {
    lra_reply(403, 'hooks_disabled', 'This server does not take hooks');
}

$hostname = strtolower(lra_post('hostname'));
$timestamp = lra_post('timestamp');
$nonce = lra_post('nonce');
$hook_id = lra_post('hookId');
$subject = strtolower(lra_post('subject'));
$signature = lra_post('signature');

if (!lra_valid_hostname($hostname) || !lra_valid_hostname($subject)) {
    lra_reply(400, 'error', 'Invalid hostname');
}
if (!lra_valid_hook_id($hook_id)) {
    lra_reply(400, 'error', 'Invalid hook ID');
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

$manifest = lra_hook_manifest($hook_id);
if ($manifest === null) {
    lra_reply(404, 'unknown_hook', "No manifest for hook $hook_id on this server");
}

foreach (array('envelope', 'payload') as $field) {
    if (!isset($_FILES[$field]) || $_FILES[$field]['error'] !== UPLOAD_ERR_OK) {
        $code = isset($_FILES[$field]) ? $_FILES[$field]['error'] : 'missing';
        lra_reply(400, 'error', "$field upload failed, error code $code");
    }
}
if ($_FILES['envelope']['size'] > 8192) {
    lra_reply(413, 'error', 'Envelope is too large');
}
if ($_FILES['payload']['size'] > $manifest['max_bytes']) {
    lra_reply(413, 'too_large', "Hook $hook_id takes at most " . $manifest['max_bytes'] . ' bytes');
}
$envelope = file_get_contents($_FILES['envelope']['tmp_name']);
$data = file_get_contents($_FILES['payload']['tmp_name']);
if ($envelope === false || $data === false) {
    lra_reply(500, 'error', 'Could not read the uploaded files');
}

$signed = "hook\n$hostname\n$timestamp\n$nonce\n$hook_id\n$subject\n" . hash('sha256', $envelope) . "\n" . hash('sha256', $data);
if (!lra_verify_signature($record['cert_pem'], $signed, $signature)) {
    lra_reply(403, 'bad_signature', 'Signature check failed');
}

// Grants for scanner hosts that send data about other hosts come later
if ($subject !== $hostname) {
    lra_reply(403, 'not_allowed_subject', "Host $hostname may only send hooks about itself");
}

$env = lra_hook_parse_envelope($envelope);
if (!isset($env['HOOK_ID']) || $env['HOOK_ID'] !== $hook_id || !isset($env['SUBJECT']) || strtolower($env['SUBJECT']) !== $subject) {
    lra_reply(400, 'error', 'Envelope does not match the request');
}
if (isset($env['SHA256']) && strtolower($env['SHA256']) !== hash('sha256', $data)) {
    lra_reply(400, 'error', 'Envelope SHA256 does not match the payload');
}

$dir = lra_hook_dir($subject, $hook_id);
$last = lra_read_meta("$dir/latest.meta");
if (isset($last['RECEIVED_ETIME']) && time() - (int)$last['RECEIVED_ETIME'] < $manifest['min_interval']) {
    lra_reply(429, 'too_soon', "Hook $hook_id was received less than " . $manifest['min_interval'] . ' seconds ago');
}
if (!lra_use_nonce($hostname, $nonce)) {
    lra_reply(403, 'replay', 'Request was already used');
}

$format = lra_hook_format($manifest, $env);
$error = '';
$lines = lra_hook_parse($format, $data, $error);
if ($error !== '') {
    $lines = 'UNKNOWN - ' . $subject . ' hook ' . $hook_id . ' payload could not be read as ' . $format . ': ' . lra_hook_clean_value($error, 200) . "\n";
}

$meta = array();
foreach (array('HOOK_ID', 'TITLE', 'SUBJECT', 'FILE_NAME', 'CONTENT_TYPE', 'COLLECTED', 'COLLECTED_ETIME', 'SOURCE', 'AGENT_VERSION') as $k) {
    if (isset($env[$k])) {
        $meta[$k] = $env[$k];
    }
}
if (isset($meta['COLLECTED_ETIME']) && !ctype_digit($meta['COLLECTED_ETIME'])) {
    unset($meta['COLLECTED_ETIME']);
}
$meta['FORMAT'] = $format;
$meta['SHA256'] = hash('sha256', $data);
$meta['BYTES'] = (string)strlen($data);
$meta['SENDER'] = $hostname;
$meta['REMOTE_ADDR'] = lra_remote_addr();
$meta['RECEIVED'] = gmdate('Y-m-d H:i:s') . ' UTC';
$meta['RECEIVED_ETIME'] = (string)time();
$meta['PARSE'] = $error === '' ? 'ok' : 'error';

if (!lra_hook_store($subject, $manifest, $data, $lines, $meta)) {
    lra_reply(500, 'error', 'Could not save the hook payload');
}

$record['last_seen'] = gmdate('Y-m-d H:i:s') . ' UTC';
$record['last_addr'] = lra_remote_addr();
lra_save_agent($record);

lra_reply(200, 'ok', "Hook $hook_id for $subject saved, " . strlen($data) . " bytes, format $format" . ($error === '' ? '' : ' (parse error: ' . $error . ')'));
?>
