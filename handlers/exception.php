<?php

function exception_handler($e)
{
    $exception = [
        "type" => "exception",
        "code" => $e->getCode(),
        "file" => $e->getFile(),
        "line" => $e->getLine(),
        "trace" => $e->getTraceAsString(),
        "message" => $e->getMessage(),
        "date" => date('Y-m-d H:i:s'),
    ];

    Logger::write($exception);

    if (isset($GLOBALS['global']['http_response_code']) && $GLOBALS['global']['http_response_code'] !== 200) {
        http_response_code($GLOBALS['global']['http_response_code']);
    } else {
        http_response_code(500);
    }

    header('Contet-Type: application/json');
    echo json_encode(['status' => false, 'type' => 'exception']);
    exit(-2);
}
