<?php

class Logger
{
    public static function write(array $log)
    {
        if (!file_exists(getcwd() . '/logs')) {
            mkdir(getcwd() . '/logs');
        }

        $date = date('Y-m-d');
        $log_file_name = getcwd() . '/logs/' . $date . '.json';
        if (file_exists($log_file_name)) {
            $old_logs = file_get_contents($log_file_name);
            $old_logs = json_decode($old_logs, true);
            $old_logs[] = $log;
            $log = $old_logs;
        } else {
            $old_logs = [];
            $old_logs[] = $log;
            $log = $old_logs;
        }

        file_put_contents($log_file_name, json_encode($log));
    }
}
