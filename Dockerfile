FROM php:7.2.8-fpm-alpine3.7
LABEL maintainer "nao_sec <info@nao-sec.org>"

ADD . /var/www/html

RUN apk add --no-cache mono --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing && \
    apk add --no-cache --virtual=.build-dependencies ca-certificates && \
    apk add --no-cache libzip-dev && \
    cert-sync /etc/ssl/certs/ca-certificates.crt && \
    apk del .build-dependencies && \
    docker-php-ext-install zip && \
    chown www-data:www-data -R /var/www/html && \
    rm -rf /var/www/html/{logs,uploads,swf,malware}/* /var/www/html/api/result/* && \
    echo "file_uploads = On" > /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "memory_limit = 64M" >> /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "upload_max_filesize = 64M" >> /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "post_max_size = 64M" >> /usr/local/etc/php/conf.d/ektotal.ini && \
    echo "max_execution_time = 600" >> /usr/local/etc/php/conf.d/ektotal.ini
