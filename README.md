# EKTotal
`EKTotal` is an integrated analysis tool that can automatically analyze the traffic of Drive-by Download attacks. The proposed software package can identify four types of Exploit Kits such as RIG and Magnitude, and more than ten types of attack campaigns such as Seamless and Fobos. EKTotal can also extract exploit codes and malware. The proposed heuristic analysis engine is based on Exploit Kit tracking research conducted since 2017, and is known as team ["nao_sec"](https://twitter.com/nao_sec). EKTotal provides a user-friendly web interface and powerful automated analysis functions. Thus, EKTotal can assist SOC operators and CSIRT members and researchers.

## Features
- Identification of malicious traffic
  - Extract over 10 types of attack campaigns out of enormous traffic data
- Automatic analysis of Exploit Kit
  - Automatically analyzes 4 types of exploit kits, de-obfuscates the exploit codes, and decrypts the malware
- User-friendly Web-UI
  - You can know the result at a glance
- Lazy Gate Estimation
  - Estimate where the redirect was from EK. This feature makes it very easy to reproduce traffic

## Requirements
- PHP 7
- Web Server (e.g. `nginx + php-fpm`)
- [hidd3ncod3s/pcap2saz](https://github.com/hidd3ncod3s/pcap2saz)
- Environment that can run .NET binaries (e.g. `.NET Framework`, `Mono`)

## Installation
### Docker
1. Git clone this repository
2. Git clone [hidd3ncod3s/pcap2saz](https://github.com/hidd3ncod3s/pcap2saz) and build it
3. Put `FiddlerCore.dll`, `Ionic.Zip.dll` and `pcap2saz.exe` under `ektotal/bin`
4. If you want to submit malwares to VirusTotal, set the API key to `post_vt.php`
5. Run `docker-compose up -d`

### Build
1. Git clone this repository
2. Git clone [hidd3ncod3s/pcap2saz](https://github.com/hidd3ncod3s/pcap2saz) and build it
3. Put `FiddlerCore.dll`, `Ionic.Zip.dll` and `pcap2saz.exe` under `ektotal/bin`
4. If you want to submit malwares to VirusTotal, set the API key to `post_vt.php`
5. Configure & run Web Server  
   document_root is `/frontend/dist` and document_root of the URL containing `/api` is `/`  
   For example, when using `nginx + php-fpm`

```
server {
  listen 80;
  server_name _;
  client_max_body_size 30M;

  location / {
      root   /path/to/directory/frontend/dist;
      index  index.html;
      try_files $uri $uri/ /index.html;
  }

  location /api {
      root   /path/to/directory;
      index  index.html index.htm index.php;
      try_files $uri /index.php?$query_string;
  }

  location ~ \.php$ {
      root           /path/to/directory;
      fastcgi_pass   127.0.0.1:9000;
      fastcgi_index  index.php;
      fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
      include        fastcgi_params;
  }
}
```

## Usage
Just submit pcap or saz file

### Sample Traffic Data
- RIG Exploit Kit
  - [https://gist.github.com/koike/346ee11f53adabb47e06384e335536bb](https://gist.github.com/koike/346ee11f53adabb47e06384e335536bb)
- GrandSoft Exploit Kit
  - [https://gist.github.com/koike/a2e66c2570af706d566b3629a814d77c](https://gist.github.com/koike/a2e66c2570af706d566b3629a814d77c)
- Bloodlust Drive-by
  - [https://gist.github.com/koike/3d071530649a8b715ed71fd42fa78aa1](https://gist.github.com/koike/3d071530649a8b715ed71fd42fa78aa1)
- Magnitude Exploit Kit
  - [https://www.virustotal.com/#/file/b1b51bc0b48789ad64b178a6c5e7555734b02aba16392341ef7f86378eb9fcd0](https://www.virustotal.com/#/file/b1b51bc0b48789ad64b178a6c5e7555734b02aba16392341ef7f86378eb9fcd0) (Ref: https://malware.dontneedcoffee.com/2018/03/CVE-2018-4878.html#magnitude)

![](https://i.imgur.com/j9qMVSe.png)  
![](https://i.imgur.com/9a0PHnN.png)  
![](https://i.imgur.com/gV2nlbm.png)  
![](https://i.imgur.com/RnOAxbo.png)

## License
`EKTotal` is open-sourced software licensed under the [MIT License](LICENSE)

## Change Log
- 2018/05/04 - 1.0.0 - First Release
- 2018/09/30 - 1.1.0 - Bugfix (gzdecode)
- 2018/10/09 - 1.2.0 - Add Fallout analyzer
- 2019/07/01 - 2.0.0 - Add Lazy Gate Estimation

## TODO
- Add function to resolve domain name
- Add function to create traffic chain

## Thanks
- [@EKFiddle](https://twitter.com/EKFiddle) - [GitHub Repository](https://github.com/malwareinfosec/EKFiddle)
- [hidd3ncod3s/pcap2saz](https://github.com/hidd3ncod3s/pcap2saz)
- All beta testers
