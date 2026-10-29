<?php
// lra_auth.php
// Who may open admin.php. Include it at file
// scope (not inside a function) after lra_lib.php, and define
// LRA_AUTH_PAGE first ('admin'). Sets $lra_viewer to the
// signed in user name.
//
// [admin] login in server.ini picks the login:
//   basic  web server authentication (.htaccess AuthType Basic), the
//          page needs REMOTE_USER unless require_remote_user = 0
//   drsm   the DataReel System Monitor dashboard login: the pages must be
//          under the dashboard's web folder (they share its session
//          cookie), and drsm_config points at the dashboard's
//          config/drsm.php. Users, lockouts and sign out are the
//          dashboard's.

if (isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    http_response_code(404);
    exit;
}

$lra_auth_cfg = lra_config();
$lra_viewer = '';

if ($lra_auth_cfg['admin']['login'] === 'drsm') {
    $lra_drsm_config = $lra_auth_cfg['admin']['drsm_config'];
    if ($lra_drsm_config !== '' && $lra_drsm_config[0] !== '/') {
        $lra_drsm_config = __DIR__ . '/' . $lra_drsm_config;
    }
    if ($lra_drsm_config === '' || !is_readable($lra_drsm_config)) {
        http_response_code(500);
        echo "login = drsm needs drsm_config in server.ini to point at the dashboard's config/drsm.php.\n";
        exit;
    }
    // Loaded here at file scope, so the dashboard settings are globals as
    // its code expects. drsm_lib.php sends anyone not signed in to the
    // dashboard login page, which brings them back here afterwards.
    require_once $lra_drsm_config;
    require_once "{$WWWdir}/php/drsm_lib.php";
    $lra_viewer = (isset($AUTHuser) && $AUTHuser !== '') ? $AUTHuser : 'dashboard';
}
else {
    $lra_viewer = isset($_SERVER['REMOTE_USER']) ? (string)$_SERVER['REMOTE_USER'] : '';
    if ($lra_auth_cfg['admin']['require_remote_user'] === '1' && $lra_viewer === '') {
        http_response_code(403);
        echo "This page must be protected by web server authentication (REMOTE_USER is not set).\n";
        exit;
    }
    if ($lra_viewer === '') {
        $lra_viewer = 'admin';
    }
}
?>
