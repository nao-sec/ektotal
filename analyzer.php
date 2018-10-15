<?php

class Analyzer
{
    public static function rig($response_body, string $content_type): array
    {
        if (strpos($content_type, 'text/html') !== false) {
            $rig_info = self::get_rig_landing_page_info($response_body);
            $enc_key = $rig_info['enc_key'];
            $cve_numbers = $rig_info['cve_numbers'];
            return [
                'type' => 'landing',
                'enc_key' => $enc_key,
                'cve_numbers' => $cve_numbers,
            ];
        } else if (strpos($content_type, 'application/x-shockwave-flash') !== false) {
            return [
                'type' => 'swf',
            ];
        } else if (strpos($content_type, 'application/x-msdownload') !== false) {
            return [
                'type' => 'malware',
            ];
        } else {
            return [
                'type' => 'undefined',
            ];
        }
    }

    public static function grandsoft($response_body, string $content_type): array
    {
        //
    }

    public static function kaixin($response_body, string $content_type): array
    {
        //
    }

    public static function magnitude($response_body, string $content_type): array
    {
        //
    }

    public static function sundown($response_body, string $content_type): array
    {
        if (strpos($content_type, 'text/html') !== false) {
            return self::get_rig_landing_page_info($response_body);
        } else {
            return [];
        }
    }

    public static function greenflash($response_body, string $content_type): array
    {
        //
    }

    public static function fallout($response_body, string $content_type): array
    {
        if (strpos($content_type, 'text/html') !== false) {
            $fallout_info = self::get_fallout_landing_page_info($response_body);
            $host = $fallout_info['host'];
            $enc_key = $fallout_info['enc_key'];
            $cve_numbers = $fallout_info['cve_numbers'];
            return [
                'type' => 'landing',
                'host' => $host,
                'enc_key' => $enc_key,
                'cve_numbers' => $cve_numbers,
            ];
        } else if (strpos($content_type, 'application/octet-stream') !== false) {
            return [
                'type' => 'malware',
            ];
        } else {
            return [
                'type' => 'undefined',
            ];
        }
    }

    private static function get_fallout_landing_page_info(string $html): array
    {
        if (strlen($html) === 0) {
            return ['host' => '', 'enc_key' => null, 'cve_numbers' => []];
        }

        $enc_element = explode("getElementById('", $html)[1];
        $enc_element = explode("'", $enc_element)[0];
        $enc_str = explode($enc_element . '">', $html)[1];
        $enc_str = explode('</', $enc_str)[0];

        $base_str = '';
        preg_match("/='[a-zA-Z0-9\/\+=]{65}';/", $html, $m);
        if (count($m) > 0) {
            $base_str = $m[0];
            $base_str = explode("'", $base_str)[1];
        }

        $key = '';
        preg_match("/='[a-zA-Z]{4,16}';/", $html, $m);
        if (count($m) > 0) {
            $key = $m[0];
            $key = explode("'", $key)[1];
        }

        $exploit_code = self::fallout_landing_decode($enc_str, $base_str, $key);

        if (strpos($exploit_code, 'Class_Terminate') !== false && strpos($exploit_code, 'msvcrt.dll') !== false) {
            $shellcode = explode('&Unescape("', $exploit_code)[1];
            $shellcode = explode('"', $shellcode)[0];
            $shellcode = explode('%u', $shellcode);
            $tmp = [];
            foreach ($shellcode as $s) {
                $a = substr($s, 0, 2);
                $b = substr($s, 2, 2);

                $a = chr(hexdec($a));
                $b = chr(hexdec($b));

                $tmp[] = $b;
                $tmp[] = $a;

            }
            $tmp = implode('', $tmp);
            $shellcode_key = ord($tmp[0xf]);

            $decoded_shellcode = [];
            for ($i = 0; $i < strlen($tmp); $i++) {
                $decoded_shellcode[$i] = chr(ord($tmp[$i]) ^ 0x4F);
            }
            $decoded_shellcode = implode('', $decoded_shellcode);
            $decoded_shellcode = substr($decoded_shellcode, 0, strlen($decoded_shellcode) - 7);
            $decoded_shellcode = explode(';', $decoded_shellcode);

            $key = $decoded_shellcode[count($decoded_shellcode) - 2];
            $url = $decoded_shellcode[count($decoded_shellcode) - 1];
            $host = parse_url($url, PHP_URL_HOST);

            return ['host' => $host, 'enc_key' => $key, 'cve_numbers' => ['CVE-2018-8174']];
        }

        return ['host' => '', 'enc_key' => null, 'cve_numbers' => []];
    }

    public static function fallout_step3(string $enc_str, string $key)
    {
        $tmp = null;
        $arr = [];
        $num = 0;
        $str = '';

        for ($i = 0; $i < 256; $i++) {
            $arr[$i] = $i;
        }

        for ($i = 0; $i < 256; $i++) {
            $num = ($num + $arr[$i] + ord($key[$i % strlen($key)])) % 256;
            $tmp = $arr[$i];
            $arr[$i] = $arr[$num];
            $arr[$num] = $tmp;
        }

        $i = 0;
        $num = 0;

        for ($j = 0; $j < strlen($enc_str); $j++) {
            $num = ($num + $arr[($i + 1) % 256]) % 256;
            $i = ($i + 1) % 256;
            $tmp = $arr[$i];
            $arr[$i] = $arr[$num];
            $arr[$num] = $tmp;
            $str .= chr(ord($enc_str[$j]) ^ $arr[($arr[$i] + $arr[$num]) % 256]);
        }

        return $str;
    }

    public static function fallout_step2(string $enc_str)
    {
        $str = '';
        $j = 0;
        $k = 0;
        $l = 0;

        for ($i = 0; $i < strlen($enc_str);) {
            if (($j = ord($enc_str[$i])) < 128) {
                $str .= chr($j);
                $i++;
            } else if ($j > 191 && $j < 224) {
                $l = ord($enc_str[$i + 1]);
                $str .= chr((31 & $j) << 6 | 63 & $l);
                $i += 2;
            } else {
                $l = ord($enc_str[$i + 1]);
                $m = ord($enc_str[$i + 2]);
                $str .= chr((15 & $j) << 12 | (63 & $l) << 6 | 63 & $m);
                $i += 3;
            }
        }

        return $str;
    }

    public static function fallout_step1(string $enc_str, string $key)
    {
        $i = '';
        $j = '';
        $k = '';
        $l = '';
        $m = '';
        $n = '';
        $o = '';
        $p = 0;
        $enc_str = preg_replace("[^A-Za-z0-9\+\/\=]", "", $enc_str);

        for (; $p < strlen($enc_str);) {
            $i = strpos($key, $enc_str[$p++]) << 2 | ($l = strpos($key, $enc_str[$p++])) >> 4;
            $j = (15 & $l) << 4 | ($m = strpos($key, $enc_str[$p++])) >> 2;
            $k = (3 & $m) << 6 | ($n = strpos($key, $enc_str[$p++]));
            $o .= chr($i);
            64 != $m && ($o .= chr($j));
            64 != $n && ($o .= chr($k));
        }

        return self::fallout_step2($o);
    }

    public static function fallout_landing_decode(string $enc_str, string $base_str, string $key)
    {
        return self::fallout_step3(self::fallout_step1($enc_str, $base_str), $key);
    }

    public static function get_fallout_malware_info($enc_malware, string $enc_key, string $id): string
    {
        $malware = '';
        if (strlen($enc_malware) > 0) {
            for ($i = 0; $i < strlen($enc_malware); $i++) {
                $malware .= chr(ord($enc_malware[$i]) ^ ord($enc_key[$i % strlen($enc_key)]));
            }
        }

        $sha256 = hash('sha256', $malware);
        if (!file_exists(getcwd() . '/malware')) {
            mkdir(getcwd() . '/malware');
        }
        $malware_file_path = getcwd() . '/malware/' . $sha256 . '.bin';
        file_put_contents($malware_file_path, $malware);
        self::post_vt($malware_file_path, $id);

        return $sha256;
    }

    private static function get_rig_landing_page_info(string $html): array
    {
        if (strlen($html) === 0) {
            return ['enc_key' => null, 'cve_numbers' => []];
        }

        if (strpos($html, 'var s = ') !== false) {
            //
        } else {
            return ['enc_key' => null, 'cve_numbers' => []];
        }

        $code = explode('<script>', $html);
        unset($code[0]);
        $code = array_values($code);

        for ($i = 0; $i < count($code); $i++) {
            $code[$i] = explode('var s = "', $code[$i])[1];
            $code[$i] = explode('";', $code[$i])[0];
            $code[$i] = str_replace('"+"', '', $code[$i]);
            $code[$i] = base64_decode($code[$i]);
        }

        $key = null;
        for ($i = 0; $i < count($code); $i++) {
            preg_match_all('/key=".{1,}"/', $code[$i], $key);
            if (count($key) > 0) {
                $key = $key[0];
            }
            if (count($key) > 0) {
                $key = end($key);
                $key = explode('"', $key)[1];
                break;
            } else {
                $key = null;
            }
        }

        for ($i = 0; $i < count($code); $i++) {
            if (strpos($code[$i], 'GogoGoA') !== false && strpos($code[$i], 'LikeMeLike') !== false && strpos($code[$i], 'ProtectMe') !== false) {
                $code[$i] = 'CVE-2016-0189';
            } else if (strpos($code[$i], 'k1 = 1') !== false && strpos($code[$i], 'k2 = 1999 + k1') !== false && strpos($code[$i], 'fix1 = "%u4141"') !== false && strpos($code[$i], 'fix22 = "%u0000"') !== false) {
                $code[$i] = 'CVE-2016-0189';
            } else if (strpos($code[$i], 'fr=String.fromCharCode') !== false && strpos($code[$i], '<object type="application/x-shockwave-flash"') !== false) {
                $code[$i] = 'SWF Exploit';
            } else if (strpos($code[$i], 'fr=String.fromCharCode') !== false && strpos($code[$i], '2, 3, 5, 7, 11, 13, 17') !== false) {
                $code[$i] = 'CVE-2015-2419';
            } else if (strpos($code[$i], 'while (num > 0xF)') !== false && strpos($code[$i], '70.86.130.70.132.84') !== false) {
                $code[$i] = 'CVE-2013-2551';
            } else if (strpos($code[$i], '1.123456789012345678901234567890') !== false) {
                $code[$i] = 'CVE-2014-6332';
            } else if (strpos($code[$i], 'Class_Terminate') !== false) {
                $code[$i] = 'CVE-2018-8174';
            } else {
                $code[$i] = 'Unknown Exploit';
            }
        }

        for ($i = 0; $i < count($code); $i++) {
            if (strpos($code[$i], 'CVE-') !== false || strpos($code[$i], 'SWF Exploit') !== false || strpos($code[$i], 'Unknown Exploit') !== false) {
                //
            } else {
                unset($code[$i]);
            }
        }

        $code = array_merge($code);
        return ['enc_key' => $key, 'cve_numbers' => $code];
    }

    public static function get_rig_malware_info($enc_malware, string $enc_key, string $id): string
    {
        $malware = self::rc4_calc($enc_malware, $enc_key);
        $sha256 = hash('sha256', $malware);
        if (!file_exists(getcwd() . '/malware')) {
            mkdir(getcwd() . '/malware');
        }
        $malware_file_path = getcwd() . '/malware/' . $sha256 . '.bin';
        file_put_contents($malware_file_path, $malware);
        self::post_vt($malware_file_path, $id);

        return $sha256;
    }

    public static function get_sundown_malware_info($enc_malware, string $enc_key, string $id): string
    {
        $malware = self::rc4_calc($enc_malware, $enc_key);
        $sha256 = hash('sha256', $malware);
        if (!file_exists(getcwd() . '/malware')) {
            mkdir(getcwd() . '/malware');
        }
        $malware_file_path = getcwd() . '/malware/' . $sha256 . '.bin';
        file_put_contents($malware_file_path, $malware);
        self::post_vt($malware_file_path, $id);

        return $sha256;
    }

    public static function get_rig_swf_info($swf, string $id): array
    {
        $sha256 = hash('sha256', $swf);
        if (!file_exists(getcwd() . '/swf')) {
            mkdir(getcwd() . '/swf');
        }
        $swf_file_path = getcwd() . '/swf/' . $sha256 . '.swf';
        file_put_contents($swf_file_path, $swf);
        self::post_vt($swf_file_path, $id);

        // check swf cve
        $cve_number = [];
        if (file_exists(getcwd() . '/rules/swf_cve.json')) {
            $swf_cve_data = file_get_contents(getcwd() . '/rules/swf_cve.json');
            $swf_cve_data = json_decode($swf_cve_data, true);

            if (isset($swf_cve_data[$sha256])) {
                $cve_number[] = $swf_cve_data[$sha256];
            }
        }

        return ['sha256' => $sha256, 'cve_numbers' => $cve_number];
    }

    private static function rc4_calc(string $data, string $key): string
    {
        $s = [];
        for ($i = 0; $i < 256; $i++) {
            $s[$i] = $i;
        }

        $j = 0;
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
            list($s[$i], $s[$j]) = [$s[$j], $s[$i]];
        }

        $i = $j = 0;
        $ret = '';
        for ($k = 0; $k < strlen($data); $k++) {
            $i = ($i + 1) % 256;
            $j = ($j + $s[$i]) % 256;
            list($s[$i], $s[$j]) = [$s[$j], $s[$i]];
            $ret .= $data[$k] ^ chr($s[($s[$i] + $s[$j]) % 256]);
        }

        return $ret;
    }

    private static function post_vt(string $file_path, string $id)
    {
        $command = 'php ' . getcwd() . '/post_vt.php "' . $file_path . '" "' . $id . '"';
        self::exec_async($command);
    }

    private static function exec_async(string $command)
    {
        if (PHP_OS !== 'WIN32' && PHP_OS !== 'WINNT') {
            exec('nohup ' . $command . ' > /dev/null 2>&1 &');
        } else {
            $fp = popen('start "" ' . $command, 'r');
            pclose($fp);
        }
    }

    public static function get_grandsoft_malware_info($enc_malware, $enc_key, string $id): string
    {
        $malware = self::decode_grandsoft_malware($enc_malware, $enc_key);
        $sha256 = hash('sha256', $malware);
        if (!file_exists(getcwd() . '/malware')) {
            mkdir(getcwd() . '/malware');
        }
        $malware_file_path = getcwd() . '/malware/' . $sha256 . '.bin';
        file_put_contents($malware_file_path, $malware);
        self::post_vt($malware_file_path, $id);

        return $sha256;
    }

    private static function decode_grandsoft_malware($enc_malware, $enc_key)
    {
        $enc_key = intval($enc_key);

        $data = [];
        for ($i = 0; $i < strlen($enc_malware); $i++) {
            $enc_key = ($enc_key + 0xAA) & 0xFF;
            $enc_key = $enc_key ^ 0x48;
            $data[] = chr(ord($enc_malware[$i]) ^ $enc_key);
        }

        return implode('', $data);
    }

    public static function get_magnitude_malware_info($malware, string $id): string
    {
        $sha256 = hash('sha256', $malware);
        if (!file_exists(getcwd() . '/malware')) {
            mkdir(getcwd() . '/malware');
        }
        $malware_file_path = getcwd() . '/malware/' . $sha256 . '.bin';
        file_put_contents($malware_file_path, $malware);
        self::post_vt($malware_file_path, $id);

        return $sha256;
    }
}
