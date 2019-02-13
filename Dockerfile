FROM php:7.3.2-fpm-stretch
LABEL maintainer "nao_sec <info@nao-sec.org>"

ADD . /var/www/html

RUN apt update -y && \
    apt upgrade -y && \
    apt install -y apt-transport-https dirmngr zlib1g-dev libzip-dev && \
    apt-key adv --no-tty --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF && \
    echo "deb https://download.mono-project.com/repo/debian stable-stretch main" | tee /etc/apt/sources.list.d/mono-official-stable.list && \
    apt update -y && \
    apt install -y mono-devel && \
    apt clean -y && \
    rm -rf /var/lib/apt/lists/* && \
    docker-php-ext-install zip && \
    chown www-data:www-data -R /var/www/html && \
    rm -rf /var/www/html/{logs,uploads,swf,malware}/* /var/www/html/api/result/* && \
    echo "file_uploads = On" > /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "memory_limit = 64M" >> /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "upload_max_filesize = 64M" >> /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "post_max_size = 64M" >> /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "max_execution_time = 600" >> /usr/local/etc/php/conf.d/ektotal.ini
