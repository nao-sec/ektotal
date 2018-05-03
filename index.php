<?php

require_once 'handlers/error.php';
require_once 'handlers/exception.php';
require_once 'logger.php';
require_once 'router.php';

set_error_handler('error_handler');
set_exception_handler('exception_handler');
$GLOBALS['global']['http_response_code'] = 200;

Router::exec();
