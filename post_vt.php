<?php

/*****************************
 * Set your VirusTotal API key
 *****************************/
$api_key = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

// ---
// ---
// ---

require_once 'handlers/error.php';
require_once 'handlers/exception.php';

require_once 'logger.php';

set_error_handler('error_handler');
set_exception_handler('exception_handler');

if ($argc < 2) {
    throw new Exception('Invalid arguments');
}

$file_path = $argv[1];
$cfile = curl_file_create($file_path);

$post = ['apikey' => $api_key, 'file' => $cfile];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://www.virustotal.com/vtapi/v2/file/scan');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_ENCODING, 'gzip,deflate');
curl_setopt($ch, CURLOPT_USERAGENT, "gzip, EKTotal");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post);

$result = curl_exec($ch);
$status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$vt_url = '';
if ($status_code === 200) {
    $json = json_decode($result, true);
    $vt_url = $json['permalink'];
    $vt_url = explode('analysis/', $vt_url);
    if (count($vt_url) === 2) {
        $vt_url = $vt_url[0] . 'analysis/';
    } else {
        $vt_url = '';
    }
} else {
    $vt_url = '';
}
curl_close($ch);

exit(0);
