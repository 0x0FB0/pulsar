FROM python:3.8.2-buster
ENV PYTHONUNBUFFERED 1

COPY secrets_storage/sandbox_key /etc/ssh/sandbox_key
RUN chmod 0600 /etc/ssh/sandbox_key

#RUN apt-get update && apt-get install -y nginx python3-dev apache2-utils libexpat1 netcat less screen \
# openssl libmariadb-dev libcurl4-openssl-dev libssl-dev gcc

RUN apt-get update && apt-get install -y --allow-downgrades libssl1.1 libgnutls30 libcurl4 libpython3.7-minimal libcurl4-openssl-dev python3.7-minimal python3-minimal mime-support libmpdec2 libpython3.7-stdlib python3.7 libpython3-stdlib python3 less sensible-utils bzip2 libmagic-mgc libmagic1 file krb5-locales manpages netcat-traditional ucf xz-utils libapr1 libaprutil1 apache2-utils binutils-common libbinutils binutils-x86-64-linux-gnu binutils libisl19 libmpfr6 libmpc3 cpp-8 cpp python3-lib2to3 python3-distutils dh-python fonts-dejavu-core fontconfig-config libcc1-0 libgomp1 libitm1 libatomic1 libasan5 liblsan0 libtsan0 libubsan1 libmpx2 libquadmath0 libgcc-8-dev gcc-8 gcc geoip-database libbsd0 libc-dev-bin linux-libc-dev libc6-dev libkeyutils1 libkrb5support0 libk5crypto3 libkrb5-3 libgssapi-krb5-2 libsasl2-modules-db libsasl2-2 libldap-common libldap-2.4-2 libnghttp2-14 libpsl5 librtmp1 libssh2-1 libevent-2.1-6 libexpat1-dev libpng16-16 libfreetype6 libfontconfig1 libjpeg62-turbo libjbig0 libwebp6 libtiff5 libxau6 libxdmcp6 libxcb1 libx11-data libx11-6 libxpm4 libgd3 libgeoip1 libgmpxx4ldbl libgmp-dev libunbound8 libgnutls-dane0 libgnutls-openssl27 libgnutlsxx28 libidn2-dev libp11-kit-dev libtasn1-6-dev nettle-dev libgnutls28-dev libicu63 mysql-common mariadb-common libmariadb3 zlib1g-dev libmariadb-dev lsb-base nginx-common libnginx-mod-http-auth-pam libxml2 libxslt1.1 libnginx-mod-http-dav-ext libnginx-mod-http-echo libnginx-mod-http-geoip libnginx-mod-http-image-filter libnginx-mod-http-subs-filter libnginx-mod-http-upstream-fair libnginx-mod-http-xslt-filter libnginx-mod-mail libnginx-mod-stream libpython3.7 libpython3.7-dev libpython3-dev libsasl2-modules libssl-dev libtasn1-doc libutempter0 manpages-dev netcat nginx-full nginx publicsuffix python3.7-dev python3-dev screen openssh-client procps

RUN adduser --system --no-create-home --disabled-login nginx
RUN mkdir /etc/ssl/celery_client
RUN mkdir /portal
COPY portal /portal/
RUN touch /portal/logs/django.log
RUN touch /portal/logs/celery.log
WORKDIR /portal

COPY /portal/conf/site.conf /etc/nginx/sites-enabled/pulsar

RUN chmod a+x /portal/conf/gunicorn.sh

RUN chown -R nginx:nogroup /portal/

RUN pip install --upgrade pip && pip install -r requirements.txt
