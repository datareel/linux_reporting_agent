<?php
// register.php
// Agents post their self-signed certificate here before they send any
// report. A new agent is approved right away when it sends the right
// enrollment token and auto_approve_with_token = 1, otherwise it waits for
// an admin to approve it on admin.php.
//
// Request fields: hostname, timestamp, nonce, cert (PEM), enrollment_token,
// signature (base64 RSA SHA-256 over
// "register\n<hostname>\n<timestamp>\n<nonce>\n<sha256 hex of cert>")

require_once __DIR__ . '/lra_lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    lra_reply(405, 'error', 'POST required');
}

$cfg = lra_config();
$hostname = strtolower(lra_post('hostname'));
$timestamp = lra_post('timestamp');
$nonce = lra_post('nonce');
$cert_pem = lra_post('cert');
$token = lra_post('enrollment_token');
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

$cert = openssl_x509_read($cert_pem);
if ($cert === false) {
    lra_reply(400, 'error', 'Invalid certificate');
}
$parsed = openssl_x509_parse($cert);
$cn = isset($parsed['subject']['CN']) ? strtolower($parsed['subject']['CN']) : '';
if ($cn !== $hostname) {
    lra_reply(400, 'error', 'Certificate CN does not match hostname');
}

// The signature proves the agent holds the private key for this certificate
$signed = "register\n$hostname\n$timestamp\n$nonce\n" . hash('sha256', $cert_pem);
if (!lra_verify_signature($cert_pem, $signed, $signature)) {
    lra_reply(403, 'bad_signature', 'Signature check failed');
}
if (!lra_use_nonce($hostname, $nonce)) {
    lra_reply(403, 'replay', 'Request was already used');
}

$fingerprint = lra_key_fingerprint($cert_pem);
if ($fingerprint === false) {
    lra_reply(400, 'error', 'Could not read the certificate public key');
}

$record = lra_load_agent($hostname);
$now = gmdate('Y-m-d H:i:s') . ' UTC';

if ($record !== null) {
    // A different key for a known hostname, for example a reinstalled
    // computer, needs an admin to delete the old registration first
    if (!hash_equals($record['key_fingerprint'], $fingerprint)) {
        lra_reply(409, 'key_mismatch', "Host $hostname is registered with a different key. An admin must delete the old registration.");
    }
    $record['last_register'] = $now;
    $record['last_addr'] = lra_remote_addr();
    lra_save_agent($record);
    lra_reply(200, $record['status']);
}

$server_token = $cfg['registration']['enrollment_token'];
$token_ok = false;
if ($server_token !== '' && $token !== '') {
    if (!hash_equals($server_token, $token)) {
        lra_reply(403, 'bad_token', 'Wrong enrollment token');
    }
    $token_ok = true;
}

$approved = $token_ok && $cfg['registration']['auto_approve_with_token'] === '1';
$record = array(
    'hostname' => $hostname,
    'status' => $approved ? 'approved' : 'pending',
    'key_fingerprint' => $fingerprint,
    'cert_pem' => $cert_pem,
    'registered_at' => $now,
    'approved_at' => $approved ? $now : '',
    'approved_by' => $approved ? 'enrollment token' : '',
    'last_register' => $now,
    'last_seen' => '',
    'last_addr' => lra_remote_addr(),
);
if (!lra_save_agent($record)) {
    lra_reply(500, 'error', 'Could not save the registration');
}
lra_reply(200, $record['status']);
?>
