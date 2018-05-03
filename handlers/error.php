<?php

function error_handler($code, $message, $file, $line)
{
    $error = [
        "type" => "error",
        "code" => $code,
        "file" => $file,
        "line" => $line,
        "message" => $message,
        "date" => date('Y-m-d H:i:s'),
    ];

    Logger::write($error);

    if (isset($GLOBALS['global']['http_response_code']) && $GLOBALS['global']['http_response_code'] !== 200) {
        http_response_code($GLOBALS['global']['http_response_code']);
    } else {
        http_response_code(500);
    }

    header('Contet-Type: application/json');
    echo json_encode(['status' => false, 'type' => 'error']);
    exit(-1);
}
