FROM php:8.4.26-apache

ARG HTTPD_VERSION=2.4.68
ARG HTTPD_SHA256=68c74d4df38c26bed4dfbdb8f3baf1eb532f3872357becc1bba5d136f6b63c06

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential \
       bison \
       libapr1-dev \
       libaprutil1-dev \
       libexpat1-dev \
       libpcre2-dev \
       libssl-dev \
       libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp \
    && curl -fsSL --retry 5 \
       -o httpd.tar.bz2 \
       "https://archive.apache.org/dist/httpd/httpd-${HTTPD_VERSION}.tar.bz2" \
    && echo "${HTTPD_SHA256}  httpd.tar.bz2" | sha256sum -c - \
    && tar xjf httpd.tar.bz2 \
    && cd "httpd-${HTTPD_VERSION}" \
    && ./configure \
       --prefix="/opt/httpd-${HTTPD_VERSION}" \
       --with-apr=/usr/bin/apr-1-config \
       --with-apr-util=/usr/bin/apu-1-config \
       --enable-mpms-shared=prefork \
       --with-mpm=prefork \
       --enable-modules=most \
       --enable-so \
       --enable-authz-core \
       --enable-dir \
       --enable-mime \
       --enable-rewrite \
       --disable-ssl \
    && make -j"$(getconf _NPROCESSORS_ONLN)" \
    && make install \
    && rm -rf /tmp/httpd.tar.bz2 "/tmp/httpd-${HTTPD_VERSION}"

COPY httpd.conf /etc/httpd-php2shell.conf
COPY php.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY www/ /var/www/html/

EXPOSE 80
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["mkdir -p /out && chown -R www-data:www-data /out && exec /opt/httpd-2.4.68/bin/httpd -DFOREGROUND -f /etc/httpd-php2shell.conf"]
