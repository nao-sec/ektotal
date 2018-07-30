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
    rm -rf /var/www/html/{logs,uploads,swf,malware}/* /var/www/html/api/result/*
