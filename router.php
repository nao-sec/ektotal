<?php

require_once 'logger.php';

class Router
{
    public static function exec()
    {
        $url = $_SERVER['REQUEST_URI'];
        $path = preg_replace('/\/(?=\/)/', '', parse_url($url, PHP_URL_PATH));
        $path_parts = explode('/', $path);
        if (strlen($path_parts[1]) === 0) {
            self::view_top_page_contents();
            exit(1);
        }

        // $frontend_files = self::get_frontend_filenames();
        // foreach($frontend_files as $frontend_file) {
        //     if($path === $frontend_file) {
        //         echo file_get_contents(getcwd() . '/frontend/dist' . $frontend_file);
        //         exit(0);
        //     }
        // }

        if (count($path_parts) < 3) {
            self::view_top_page_contents();
            exit(1);
        }

        /*
        $url          => 'http://api.ektotal.com/api/submit/status?id=100'
        $api_endpoint => 'api'
        $function     => 'submit'
        $arguments    => 'status'
        $queries      =>  ['id' => '100']
         */
        $method = strtolower($_SERVER['REQUEST_METHOD']);
        $api_endpoint = strtolower($path_parts[1]);
        if ($api_endpoint !== 'api') {
            throw new Exception('Unsupported API endpoint: ' . $api_endpoint);
        }
        $function = strtolower($path_parts[2]);
        $arguments = implode('/', array_slice($path_parts, 3));
        $queries = self::parse_queries($url);

        if (!in_array($function, self::get_function_names())) {
            throw new Exception('Unsupported function: ' . $function);
        }

        require_once getcwd() . '/api/' . $function . '.php';

        if (!method_exists($function, $method)) {
            throw new Exception('Unsupported method: ' . $function . '::' . $method);
        }

        $function::$method($arguments, $queries);
    }

    public static function view_top_page_contents()
    {
        $html = file_get_contents(getcwd() . '/frontend/dist/index.html');
        echo $html;
    }

    public static function parse_queries(string $url)
    {
        $queries = [];
        $queries_str = parse_url($url, PHP_URL_QUERY);
        if (strlen($queries_str) > 1) {
            $queries_parts = explode('&', $queries_str);
            foreach ($queries_parts as $queries_part) {
                $queries_arr = explode('=', $queries_part);
                if (count($queries_arr) > 1) {
                    $queries[strtolower($queries_arr[0])] = strtolower(implode('=', array_slice($queries_arr, 1)));
                } else {
                    $queries[strtolower($queries_arr[0])] = null;
                }
            }
        }
        return $queries;
    }

    public static function get_function_names()
    {
        foreach (glob(getcwd() . '/api/*.php') as $file) {
            if (is_file($file)) {
                $supported_functions[] = pathinfo($file)['filename'];
            }
        }

        return $supported_functions;
    }

    // private static function get_frontend_filenames(): array
    // {
    //     $dir = getcwd() . '/frontend/dist';
    //     $iterator = new RecursiveIteratorIterator
    //         (
    //         new RecursiveDirectoryIterator
    //         (
    //             $dir,
    //             FilesystemIterator::SKIP_DOTS |
    //             FilesystemIterator::KEY_AS_PATHNAME |
    //             FilesystemIterator::CURRENT_AS_FILEINFO
    //         ),
    //         RecursiveIteratorIterator::LEAVES_ONLY
    //     );

    //     $list = [];
    //     foreach ($iterator as $pathname => $info) {
    //         $list[] = str_replace($dir, '', $pathname);
    //     }

    //     return $list;
    // }
}
