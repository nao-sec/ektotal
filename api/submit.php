<?php

require_once 'analyzer.php';

class submit
{
    public static function post($arguments = null, $queries = null)
    {
        if (count($_FILES) === 0) {
            self::set_http_response_header(400);
            throw new Exception('Nothing has been uploaded');
        }

        $uploads_dir = getcwd() . '/uploads/';
        if (!file_exists($uploads_dir)) {
            mkdir($uploads_dir);
        }

        $file_name = null;
        $date = date('Y-m-d_H-i-s');
        foreach ($_FILES as $file) {
            $file_name = $uploads_dir . '/' . $date . '.bin';
            if (!move_uploaded_file($file['tmp_name'], $file_name)) {
                self::set_http_response_header(400);
                throw new Exception('Faild to upload file');
            }
            break;
        }

        $file_body = file_get_contents($file_name);

        // create request id
        $file_hash = hash('sha256', $file_body);
        $id = $date . '_' . $file_hash;
        $json_path = getcwd() . '/api/result/' . $id . '.json';

        // // re-analyze flag
        // $is_forcibly_analyze = false;
        // if (isset($queries['reanalyze']) && $queries['reanalyze'] === 'true') {
        //     $is_forcibly_analyze = true;
        //     unlink($json_path);
        // }
        // // already analyzed
        // if (!$is_forcibly_analyze && file_exists($json_path)) {
        //     header('Contet-Type: application/json');
        //     echo json_encode([
        //         'id' => $id,
        //         'url' => (empty($_SERVER["HTTPS"]) ? "http://" : "https://") . $_SERVER["HTTP_HOST"] . '/api/result?id=' . $id,
        //     ]);
        //     exit(1);
        // }

        $check_file_format = self::check_magic_number($file_body);
        if (!$check_file_format['is_supported_format']) {
            self::set_http_response_header(400);
            throw new Exception('Unsupported file format');
        }
        $format = $check_file_format['format'];
        if (strpos($format, 'pcap') !== false) {
            if (!self::convert_to_saz($file_name)) {
                self::set_http_response_header(400);
                throw new Exception('Faild to convert to saz');
            }
        } else {
            rename($file_name, $file_name . '.saz');
        }
        $file_name .= '.saz';

        $max_index = self::get_zipfile_max_index($file_name);
        $max_digit = strlen($max_index);

        $traffics = [];

        $zip = new ZipArchive();
        if (!$zip->open($file_name)) {
            self::set_http_response_header(400);
            throw new Exception('Faild to open saz file');
        }

        // parse all traffic data
        for ($i = 0; $i < $max_index; $i++) {
            $index = str_pad($i + 1, $max_digit, '0', STR_PAD_LEFT);

            // 00_c.txt -> request data
            // 00_s.txt -> response data
            $file_c = $zip->getStream('raw/' . $index . '_c.txt');
            $file_s = $zip->getStream('raw/' . $index . '_s.txt');
            if (!$file_c) {
                // not exists request data
                continue;
            }

            // read data
            $request_data = '';
            $response_data = '';
            while (!feof($file_c)) {
                $request_data .= fread($file_c, 2);
            }
            if ($file_s) {
                while (!feof($file_s)) {
                    $response_data .= fread($file_s, 2);
                }
            }
            $request_data = explode("\r\n", $request_data);
            $response_data = explode("\r\n", $response_data);

            // separate response (header / body)
            $response_separator = null;
            for ($j = 0; $j < count($response_data); $j++) {
                if (strlen($response_data[$j]) === 0) {
                    $response_separator = $j;
                    break;
                }
            }
            $headers = array_slice($response_data, 0, $response_separator);
            $body = implode("\r\n", array_slice($response_data, $response_separator + 1));

            // parse request data
            $request = [];
            $request_first_line = explode(' ', $request_data[0]);
            if (count($request_first_line) < 2) {
                // invalid http request header
                continue;
            }

            $request['Method'] = strtoupper($request_first_line[0]);
            $request['Path'] = $request_first_line[1];
            for ($j = 1; $j < count($request_data); $j++) {
                $request_header = explode(': ', $request_data[$j]);
                if (count($request_header) >= 2) {
                    $request[trim($request_header[0])] = trim(implode(': ', array_slice($request_header, 1)));
                }
            }
            if (strpos($request['Path'], 'http') === 0) {
                $request['URL'] = $request['Path'];
            } else {
                $request['URL'] = $request['Host'] . $request['Path'];
            }

            // parse response data
            $response = [];
            if (isset($headers[0]) && count(explode(' ', $headers[0])) >= 2) {
                $response_first_line = explode(' ', $headers[0]);
                $response['HTTP'] = $response_first_line[0];
                $response['Status'] = $response_first_line[1];
                for ($j = 1; $j < count($headers); $j++) {
                    $response_header = explode(': ', $headers[$j]);
                    if (count($response_header) >= 2) {
                        $response['header'][trim($response_header[0])] = trim(implode(': ', array_slice($response_header, 1)));
                    }
                }

                // decode gzip
                if (isset($response['header']['Content-Encoding']) && strtolower($response['header']['Content-Encoding']) === 'gzip') {
                    if ((isset($response['header']['Transfer-Encoding']) && strtolower($response['header']['Transfer-Encoding']) === 'chunked') ||
                        isset($response['header']['transfer-encoding']) && strtolower($response['header']['transfer-encoding']) === 'chunked') {
                        $original_data = [];
                        $chunked_flag = true;
                        $pre_data_size = 0;
                        while ($chunked_flag) {
                            $body_parts = explode("\r\n", $body);
                            if (preg_match('/^[0-9a-f]{1,}$/', $body_parts[0])) {
                                $chunked_data_size = hexdec($body_parts[0]);
                                $chunked_data = implode("\r\n", array_slice($body_parts, 1));
                                $original_data[] = substr($chunked_data, 0, $chunked_data_size);

                                $other_data = substr($chunked_data, $chunked_data_size);
                                $other_data = explode("\r\n", $other_data);
                                for ($j = 0; $j < count($other_data); $j++) {
                                    if (strlen($other_data[$j]) === 0 || $other_data[$j] === '0' || $other_data[$j] === "\r\n") {
                                        unset($other_data[$j]);
                                    } else {
                                        break;
                                    }
                                }
                                $body = implode("\r\n", array_merge($other_data));
                            }

                            if (strlen($body) < 3 || strlen($body) === $pre_data_size) {
                                $chunked_flag = false;
                            }
                            $pre_data_size = strlen($body);
                        }

                        $body = file_get_contents('compress.zlib://data://text/plain;base64,' . base64_encode(implode('', $original_data)));
                    } else {
                        $body = file_get_contents('compress.zlib://data://text/plain;base64,' . base64_encode($body));
                        // if (isset($response['header']['Content-Length'])) {
                        //     $body_size = $response['header']['Content-Length'];
                        //     if (strlen($body) === $body_size) {
                        //         try
                        //         {
                        //             $body = gzdecode($body);
                        //         } catch (Exception $e) {
                        //             $body = '';
                        //         }
                        //     }
                        // } else {
                        //     try {
                        //         $body = gzdecode($body);
                        //     } catch (Exception $e) {
                        //         $body = '';
                        //     }
                        // }
                    }
                }

                // only chunked
                if (isset($response['header']['Transfer-Encoding']) && !isset($response['header']['Content-Encoding'])) {
                    $original_data = [];
                    $chunked_flag = true;
                    $pre_data_size = 0;
                    while ($chunked_flag) {
                        $body_parts = explode("\r\n", $body);
                        if (preg_match('/^[0-9a-f]{1,}$/', $body_parts[0])) {
                            $chunked_data_size = hexdec($body_parts[0]);
                            $chunked_data = implode("\r\n", array_slice($body_parts, 1));
                            $original_data[] = substr($chunked_data, 0, $chunked_data_size);

                            $other_data = substr($chunked_data, $chunked_data_size);
                            $other_data = explode("\r\n", $other_data);
                            for ($j = 0; $j < count($other_data); $j++) {
                                if (strlen($other_data[$j]) === 0 || $other_data[$j] === '0' || $other_data[$j] === '00' || $other_data[$j] === "\r\n") {
                                    unset($other_data[$j]);
                                } else {
                                    break;
                                }
                            }
                            $body = implode("\r\n", array_merge($other_data));
                        }

                        if (strlen($body) < 3 || strlen($body) === $pre_data_size) {
                            $chunked_flag = false;
                        }
                        $pre_data_size = strlen($body);
                    }

                    $body = implode('', $original_data);
                }

                $response['body'] = $body;
                $traffics[$i]['response'] = $response;
            } else {
                $traffics[$i]['response'] = null;
            }
            $traffics[$i]['request'] = $request;
        }
        $zip->close();

        // analyze http data
        $analysis_result = self::analyze_http_data($traffics, $id);
        if (!file_exists(getcwd() . '/api/result')) {
            mkdir(getcwd() . '/api/result');
        }

        $json = [
            'id' => $id,
            'created_at' => $date,
            'updated_at' => $date,
        ];
        $json['data'] = $analysis_result;
        file_put_contents($json_path, json_encode($json));

        // response data
        header('Contet-Type: application/json');
        echo json_encode([
            'id' => $id,
            'url' => (empty($_SERVER["HTTPS"]) ? "http://" : "https://") . $_SERVER["HTTP_HOST"] . '/api/result/' . $id . '.json',
        ]);
        exit(0);
    }

    private static function check_magic_number($data): array
    {
        $magic_numbers = [
            'pcapng' => [
                0x0a, 0x0d, 0x0d, 0x0a,
            ],
            'pcap' => [
                0xd4, 0xc3, 0xb2, 0xa1,
            ],
            'saz' => [
                0x50, 0x4b, 0x03, 0x04,
            ],
        ];

        $data_header = substr($data, 0, 4);

        foreach ($magic_numbers as $format => $magic_number) {
            for ($i = 0; $i < 4; $i++) {
                $magic_number[$i] = chr($magic_number[$i]);
            }
            $magic_number = implode('', $magic_number);
            if ($data_header === $magic_number) {
                return ['is_supported_format' => true, 'format' => $format];
            }
        }

        return ['is_supported_format' => false];
    }

    private static function convert_to_saz(string $file_name)
    {
        if (PHP_OS !== 'WIN32' && PHP_OS !== 'WINNT') {
            exec('mono ' . getcwd() . '/bin/pcap2saz.exe ' . $file_name, $out, $ret);
        } else {
            exec(getcwd() . '/bin/pcap2saz.exe ' . $file_name, $out, $ret);
        }

        if (is_array($out)) {
            $out = implode("\r\n", $out);
        }

        if (strpos($out, 'Success') === false) {
            return false;
        }

        return true;
    }

    private static function get_zipfile_max_index(string $file_name): int
    {
        $zip = new ZipArchive();
        if (!$zip->open($file_name)) {
            self::set_http_response_header(400);
            throw new Exception('Faild to open saz file');
        }

        $max_index = 0;
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $zip_file_name = $zip->getNameIndex($i);
            if (strpos($zip_file_name, 'raw/') !== false) {
                $num = explode('_', str_replace('raw/', '', $zip_file_name))[0];
                if (is_numeric($num)) {
                    $num = intval($num);
                    if ($num > $max_index) {
                        $max_index = $num;
                    }
                }
            }
        }
        $zip->close();

        return $max_index;
    }

    private static function analyze_http_data(array $traffics, $id): array
    {
        $allowable_http_method_list = [
            'GET',
            'POST',
            'PUT',
            'HEAD',
            'DELETE',
        ];
        $rules = self::get_parser_rules();
        $is_magnitude = false;

        for ($i = 0; $i < count($traffics); $i++) {
            $method = $traffics[$i]['request']['Method'];
            if (!in_array($method, $allowable_http_method_list)) {
                continue;
            }

            $url = $traffics[$i]['request']['URL'];
            $response_body = $traffics[$i]['response']['body'];
            $content_type = isset($traffics[$i]['response']['header']['Content-Type']) ? $traffics[$i]['response']['header']['Content-Type'] : null;
            $location_header = isset($traffics[$i]['response']['header']['Location']) ? $traffics[$i]['response']['header']['Location'] : null;
            $user_agent = isset($traffics[$i]['request']['User-Agent']) ? $traffics[$i]['request']['User-Agent'] : null;

            foreach ($rules as $rule) {
                $description = null;

                // // fix syntax error
                // if (strpos($rule['regexp'], '[\w+/]') !== false) {
                //     $rule['regexp'] = str_replace('[\w+/]', '[\w+]', $rule['regexp']);
                // }

                if ($rule['type'] === 'URI') {
                    if (preg_match($rule['regexp'], $url)) {
                        // if RIG -> analyze
                        if (strpos($rule['name'], 'RIG') !== false) {
                            $rig_analysis_result = Analyzer::rig($response_body, $content_type);

                            // landing
                            if ($rig_analysis_result['type'] === 'landing') {
                                $rule['name'] .= ' (Landing Page)';
                                $description['enc_key'] = $rig_analysis_result['enc_key'];
                                $description['cve_numbers'] = $rig_analysis_result['cve_numbers'];
                            }

                            // swf
                            if ($rig_analysis_result['type'] === 'swf') {
                                $rule['name'] .= ' (SWF Payload)';
                                $swf_info = Analyzer::get_rig_swf_info($response_body, $id);
                                $description['sha256'] = $swf_info['sha256'];
                                $description['cve_numbers'] = $swf_info['cve_numbers'];
                                $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $swf_info['sha256'];
                            }

                            // malware
                            if ($rig_analysis_result['type'] === 'malware') {
                                $rule['name'] .= ' (Malware Payload)';

                                // search enc_key
                                $enc_key = '';
                                for ($j = $i - 1; $j >= 0; $j--) {
                                    if (isset($traffics[$j]['result']) && strpos($traffics[$j]['result']['name'], 'Landing Page')) {
                                        if (isset($traffics[$j]['result']['description']['enc_key'])) {
                                            $enc_key = $traffics[$j]['result']['description']['enc_key'];
                                        }
                                    }
                                }

                                // decode malware & post vt
                                $description['sha256'] = Analyzer::get_rig_malware_info($response_body, $enc_key, $id);
                                $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];
                            }
                        }

                        if (strpos($rule['name'], 'GrandSoft') !== false) {
                            if (strpos($content_type, 'text/html') !== false) {
                                if (strpos($response_body, 'document.write("<iframe src=\'"+srcOfScript+"\'></iframe>")') !== false) {
                                    // Redirector
                                    $rule['name'] = $rule['name'] . ' (Checker)';
                                } else if (strpos($response_body, 'return String.fromCharCode(x & 0xffff) + String.fromCharCode(x >> 16);') !== false) {
                                    // CVE-2016-0189
                                    $rule['name'] = $rule['name'] . ' (Landing Page)';
                                    $description['cve_numbers'] = ['CVE-2016-0189'];
                                } else if (strpos($response_body, 'Class_Terminate()') !== false) {
                                    // CVE-2018-8174
                                    $rule['name'] = $rule['name'] . ' (Landing Page)';
                                    $description['cve_numbers'] = ['CVE-2018-8174'];
                                }
                            } else if (strpos($content_type, 'application/octet-stream') !== false) {
                                // analyze malware
                                if ($url[strlen($url) - 1] === '/') {
                                    $url = substr($url, 0, strlen($url) - 1);
                                }
                                $url_parts = explode('/', $url);
                                $enc_key = end($url_parts);
                                $description['enc_key'] = $enc_key;
                                $description['sha256'] = Analyzer::get_grandsoft_malware_info($response_body, $enc_key, $id);
                                $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];
                            }
                        }

                        if ($rule['name'] === 'Bloodlust Drive-by') {
                            if (strpos($url, 'index.php') !== false) {
                                // landing page
                                $rule['name'] .= ' (Landing Page)';

                                $landing_page_info = Analyzer::sundown($response_body, $content_type);
                                $description['enc_key'] = $landing_page_info['enc_key'];
                                $description['cve_numbers'] = $landing_page_info['cve_numbers'];
                            } else if (strpos($url, 'f.php') !== false) {
                                // redirector
                                $rule['name'] .= ' (Redirector)';
                            } else if (strpos($url, 'odt.dat') !== false) {
                                // malware payload
                                $rule['name'] .= ' (Malware Payload)';

                                // search enc_key
                                $enc_key = '';
                                for ($j = $i - 1; $j >= 0; $j--) {
                                    if (isset($traffics[$j]['result']) && strpos($traffics[$j]['result']['name'], 'Landing Page')) {
                                        if (isset($traffics[$j]['result']['description']['enc_key'])) {
                                            $enc_key = $traffics[$j]['result']['description']['enc_key'];
                                        }
                                    }
                                }

                                // decode malware & post vt
                                $description['sha256'] = Analyzer::get_sundown_malware_info($response_body, $enc_key, $id);
                                $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];
                            }
                        }

                        if (strpos($rule['name'], 'Fallout') !== false) {
                            $fallout_analysis_result = Analyzer::fallout($response_body, $content_type);

                            // landing
                            if ($fallout_analysis_result['type'] === 'landing') {
                                $rule['name'] .= ' (Landing Page)';

                                $host = $fallout_analysis_result['host'];
                                if ($host !== null && strlen($host) > 0) {
                                    $host_regexp = '/' . str_replace('.', '\\.', $host) . '/';
                                    $rules[] = ['type' => 'URI', 'name' => 'FalloutEK', 'regexp' => $host_regexp];
                                }

                                $description['enc_key'] = $fallout_analysis_result['enc_key'];
                                $description['cve_numbers'] = $fallout_analysis_result['cve_numbers'];
                            }

                            // malware
                            if ($fallout_analysis_result['type'] === 'malware') {
                                $rule['name'] .= ' (Malware Payload)';

                                // search enc_key
                                $enc_key = '';
                                for ($j = $i - 1; $j >= 0; $j--) {
                                    if (isset($traffics[$j]['result']) && strpos($traffics[$j]['result']['name'], 'Landing Page')) {
                                        if (isset($traffics[$j]['result']['description']['enc_key'])) {
                                            $enc_key = $traffics[$j]['result']['description']['enc_key'];
                                        }
                                    }
                                }

                                if (strlen($response_body) > 0) {
                                    // decode malware & post vt
                                    $description['sha256'] = Analyzer::get_fallout_malware_info($response_body, $enc_key, $id);
                                    $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];
                                }
                            }
                        }

                        if (strpos($rule['name'], 'Magnitude') !== false) {
                            $is_magnitude = true;
                        }

                        // add result
                        $traffics[$i]['result'] = [
                            'name' => $rule['name'],
                            'url' => $url,
                            'description' => $description,
                        ];
                        break;
                    }
                } else if ($rule['type'] === 'SourceCode') {
                    if (preg_match($rule['regexp'], $response_body)) {
                        if (strpos($rule['name'], 'GrandSoft') !== false) {
                            if (strpos($content_type, 'text/html') !== false) {
                                if (strpos($response_body, 'document.write("<iframe src=\'"+srcOfScript+"\'></iframe>")') !== false) {
                                    // Redirector
                                    $rule['name'] = $rule['name'] . ' (Checker)';
                                } else if (strpos($response_body, 'return String.fromCharCode(x & 0xffff) + String.fromCharCode(x >> 16);') !== false) {
                                    // CVE-2016-0189
                                    $rule['name'] = $rule['name'] . ' (Landing Page)';
                                    $description['cve_numbers'] = ['CVE-2016-0189'];
                                } else if (strpos($response_body, 'Class_Terminate()') !== false) {
                                    // CVE-2018-8174
                                    $rule['name'] = $rule['name'] . ' (Landing Page)';
                                    $description['cve_numbers'] = ['CVE-2018-8174'];
                                }
                            } else if (strpos($content_type, 'application/octet-stream') !== false) {
                                // analyze malware
                                if ($url[strlen($url) - 1] === '/') {
                                    $url = substr($url, 0, strlen($url) - 1);
                                }
                                $url_parts = explode('/', $url);
                                $enc_key = end($url_parts);
                                $description['sha256'] = Analyzer::get_grandsoft_malware_info($response_body, $enc_key, $id);
                                $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];
                            }
                        }

                        if (strpos($rule['name'], 'Fallout') !== false) {
                            $fallout_analysis_result = Analyzer::fallout($response_body, $content_type);

                            // landing
                            if ($fallout_analysis_result['type'] === 'landing') {
                                $rule['name'] .= ' (Landing Page)';

                                $host = $fallout_analysis_result['host'];
                                $host_regexp = '/' . str_replace('.', '\\.', $host) . '/';
                                $rules[] = ['type' => 'URI', 'name' => 'FalloutEK', 'regexp' => $host_regexp];

                                $description['enc_key'] = $fallout_analysis_result['enc_key'];
                                $description['cve_numbers'] = $fallout_analysis_result['cve_numbers'];
                            }

                            // malware
                            if ($fallout_analysis_result['type'] === 'malware') {
                                $rule['name'] .= ' (Malware Payload)';

                                // search enc_key
                                $enc_key = '';
                                for ($j = $i - 1; $j >= 0; $j--) {
                                    if (isset($traffics[$j]['result']) && strpos($traffics[$j]['result']['name'], 'Landing Page')) {
                                        if (isset($traffics[$j]['result']['description']['enc_key'])) {
                                            $enc_key = $traffics[$j]['result']['description']['enc_key'];
                                        }
                                    }
                                }

                                // decode malware & post vt
                                $description['sha256'] = Analyzer::get_fallout_malware_info($response_body, $enc_key, $id);
                                $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];
                            }
                        }

                        // add result
                        $traffics[$i]['result'] = [
                            'name' => $rule['name'],
                            'url' => $url,
                            'description' => $description,
                        ];
                        break;
                    }
                } else if ($rule['type'] === 'Location') {
                    if (preg_match($rule['regexp'], $location_header)) {
                        // add result
                        $traffics[$i]['result'] = [
                            'name' => $rule['name'],
                            'url' => $url,
                            'description' => $description,
                        ];
                        break;
                    }
                } else {
                    //
                }

                if ($is_magnitude) {
                    if ($user_agent === 'Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)') {
                        if (substr($response_body, 0, 2) === 'MZ') {
                            $description['sha256'] = Analyzer::get_magnitude_malware_info($response_body, $id);
                            $description['virustotal'] = 'https://www.virustotal.com/#/file/' . $description['sha256'];

                            // add result
                            $traffics[$i]['result'] = [
                                'name' => 'Magnitude Exploit Kit (Malware Payload)',
                                'url' => $url,
                                'description' => $description,
                            ];
                        }
                    }
                }
            }

            // if (strlen($traffics[$i]['response']['body']) > 1000000) {
            //     $traffics[$i]['response']['body'] = 'This data size is too large';
            // } else {
            //     $traffics[$i]['response']['body'] = base64_encode($traffics[$i]['response']['body']);
            // }
        }

        for ($i = 0; $i < count($traffics); $i++) {
            // remove traffic data
            if (isset($traffics[$i]['response']['body'])) {
                unset($traffics[$i]['response']['body']);
            }

            // set "result" & "is_malicious"
            if (isset($traffics[$i]['result'])) {
                $traffics[$i]['is_malicious'] = true;
            } else {
                $traffics[$i]['result'] = null;
                $traffics[$i]['is_malicious'] = false;
            }
        }

        $traffics = self::parse_headers($traffics);

        return $traffics;
    }

    private static function get_parser_rules(): array
    {
        $rules = [];

        // master.cache
        if (file_exists(getcwd() . '/rules/master.cache')) {
            clearstatcache();
            $filemtime = filemtime(getcwd() . '/rules/master.cache');
            $now = time();

            // if within 1 hour
            if ($filemtime > $now - 1 * 60 * 60) {
                $rules = file_get_contents(getcwd() . '/rules/master.cache');
                $rules = json_decode($rules, true);
            }
        }

        if ($rules === []) {
            // get EKFiddle's rules
            $rules_str = file_get_contents('https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt');
            $rules_array = explode("\r\n", $rules_str);
            foreach ($rules_array as $rule) {
                if (strlen($rule) > 1 && $rule[0] !== '#') {
                    $rule = str_replace("</head>","<\/head>", $rule);
                    $rule = explode("\t", $rule);
                    // ignore Phone numbers: [Extract-Phone] TAB [PhoneRegex] on EKFiddle rule
                    if( count($rule) < 3) { continue; }
                    $rules[] = [
                        'type' => $rule[0],
                        'name' => $rule[1],
                        'regexp' => '/' . $rule[2] . '/',
                    ];
                }
            }

            file_put_contents(getcwd() . '/rules/master.cache', json_encode($rules));
        }

        // get original rules
        if (file_exists(getcwd() . '/rules/custom.json')) {
            $original_rules = file_get_contents(getcwd() . '/rules/custom.json');
            $original_rules = json_decode($original_rules, true);
            foreach ($original_rules as $original_rule) {
                $rules[] = $original_rule;
            }
        }

        return $rules;
    }

    private static function parse_headers(array $traffics): array
    {
        $formatted_data = [];

        $allowable_http_method_list = [
            'GET',
            'POST',
            'PUT',
            'HEAD',
            'DELETE',
        ];

        for ($i = 0; $i < count($traffics); $i++) {
            if (isset($traffics[$i]['request']['Method']) && in_array($traffics[$i]['request']['Method'], $allowable_http_method_list)) {
                $url = $traffics[$i]['request']['URL'];
                unset($traffics[$i]['request']['URL']);
                $formatted_data[$i]['URL'] = $url;

                $formatted_data[$i]['request'] = [];
                $counter = 0;
                if (isset($traffics[$i]['request'])) {
                    foreach ($traffics[$i]['request'] as $key => $value) {
                        $formatted_data[$i]['request'][$counter] = [
                            'key' => $key,
                            'value' => $value,
                        ];
                        $counter++;
                    }
                }

                $formatted_data[$i]['response'] = [];
                $formatted_data[$i]['response']['HTTP'] = $traffics[$i]['response']['HTTP'];
                $formatted_data[$i]['response']['Status'] = $traffics[$i]['response']['Status'];
                $counter = 0;
                if (isset($traffics[$i]['response']['header'])) {
                    foreach ($traffics[$i]['response']['header'] as $key => $value) {
                        $formatted_data[$i]['response']['header'][$counter] = [
                            'key' => $key,
                            'value' => $value,
                        ];
                        $counter++;
                    }
                }

                $formatted_data[$i]['result'] = $traffics[$i]['result'];
                $formatted_data[$i]['is_malicious'] = $traffics[$i]['is_malicious'];
            }
        }

        $formatted_data = array_merge($formatted_data);
        for ($i = 0; $i < count($formatted_data); $i++) {
            $formatted_data[$i] = array_merge(['index' => $i], $formatted_data[$i]);
        }

        return $formatted_data;
    }

    private static function set_http_response_header(int $code)
    {
        $GLOBALS['global']['http_response_code'] = $code;
    }
}
