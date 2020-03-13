FROM python:3.8.2-slim-buster
ENV PYTHONUNBUFFERED 1

COPY secrets_storage/sandbox_key /etc/ssh/sandbox_key
RUN chmod 0600 /etc/ssh/sandbox_key

#RUN apt-get update && apt-get install -y nginx python3-dev apache2-utils libexpat1 netcat less screen \
# openssl libmariadb-dev libcurl4-openssl-dev libssl-dev gcc

RUN apt-get update && apt-get install -y libcurl4=7.64.0-4+deb10u1 libpython3.7-minimal=3.7.3-2+deb10u1 libcurl4-openssl-dev=7.64.0-4+deb10u1 python3.7-minimal=3.7.3-2+deb10u1 python3-minimal=3.7.3-1 mime-support=3.62 libmpdec2=2.4.2-2 libpython3.7-stdlib=3.7.3-2+deb10u1 python3.7=3.7.3-2+deb10u1 libpython3-stdlib=3.7.3-1 python3=3.7.3-1 less=487-0.1+b1 sensible-utils=0.0.12 bzip2=1.0.6-9.2~deb10u1 libmagic-mgc=1:5.35-4+deb10u1 libmagic1=1:5.35-4+deb10u1 file=1:5.35-4+deb10u1 krb5-locales=1.17-3 manpages=4.16-2 netcat-traditional=1.10-41.1 ucf=3.0038+nmu1 xz-utils=5.2.4-1 libapr1=1.6.5-1+b1 libaprutil1=1.6.1-4 apache2-utils=2.4.38-3+deb10u3 binutils-common=2.31.1-16 libbinutils=2.31.1-16 binutils-x86-64-linux-gnu=2.31.1-16 binutils=2.31.1-16 libisl19=0.20-2 libmpfr6=4.0.2-1 libmpc3=1.1.0-1 cpp-8=8.3.0-6 cpp=4:8.3.0-1 python3-lib2to3=3.7.3-1 python3-distutils=3.7.3-1 dh-python=3.20190308 fonts-dejavu-core=2.37-1 fontconfig-config=2.13.1-2 libcc1-0=8.3.0-6 libgomp1=8.3.0-6 libitm1=8.3.0-6 libatomic1=8.3.0-6 libasan5=8.3.0-6 liblsan0=8.3.0-6 libtsan0=8.3.0-6 libubsan1=8.3.0-6 libmpx2=8.3.0-6 libquadmath0=8.3.0-6 libgcc-8-dev=8.3.0-6 gcc-8=8.3.0-6 gcc=4:8.3.0-1 geoip-database=20181108-1 libbsd0=0.9.1-2 libc-dev-bin=2.28-10 linux-libc-dev=4.19.98-1 libc6-dev=2.28-10 libkeyutils1=1.6-6 libkrb5support0=1.17-3 libk5crypto3=1.17-3 libkrb5-3=1.17-3 libgssapi-krb5-2=1.17-3 libsasl2-modules-db=2.1.27+dfsg-1+deb10u1 libsasl2-2=2.1.27+dfsg-1+deb10u1 libldap-common=2.4.47+dfsg-3+deb10u1 libldap-2.4-2=2.4.47+dfsg-3+deb10u1 libnghttp2-14=1.36.0-2+deb10u1 libpsl5=0.20.2-2 librtmp1=2.4+20151223.gitfa8646d.1-2 libssh2-1=1.8.0-2.1 libevent-2.1-6=2.1.8-stable-4 libexpat1-dev=2.2.6-2+deb10u1 libpng16-16=1.6.36-6 libfreetype6=2.9.1-3+deb10u1 libfontconfig1=2.13.1-2 libjpeg62-turbo=1:1.5.2-2+b1 libjbig0=2.1-3.1+b2 libwebp6=0.6.1-2 libtiff5=4.1.0+git191117-2~deb10u1 libxau6=1:1.0.8-1+b2 libxdmcp6=1:1.1.2-3 libxcb1=1.13.1-2 libx11-data=2:1.6.7-1 libx11-6=2:1.6.7-1 libxpm4=1:3.5.12-1 libgd3=2.2.5-5.2 libgeoip1=1.6.12-1 libgmpxx4ldbl=2:6.1.2+dfsg-4 libgmp-dev=2:6.1.2+dfsg-4 libunbound8=1.9.0-2+deb10u1 libgnutls-dane0=3.6.7-4+deb10u2 libgnutls-openssl27=3.6.7-4+deb10u2 libgnutlsxx28=3.6.7-4+deb10u2 libidn2-dev=2.0.5-1+deb10u1 libp11-kit-dev=0.23.15-2 libtasn1-6-dev=4.13-3 nettle-dev=3.4.1-1 libgnutls28-dev=3.6.7-4+deb10u2 libicu63=63.1-6 mysql-common=5.8+1.0.5 mariadb-common=1:10.3.22-0+deb10u1 libmariadb3=1:10.3.22-0+deb10u1 zlib1g-dev=1:1.2.11.dfsg-1 libmariadb-dev=1:10.3.22-0+deb10u1 lsb-base=10.2019051400 nginx-common=1.14.2-2+deb10u1 libnginx-mod-http-auth-pam=1.14.2-2+deb10u1 libxml2=2.9.4+dfsg1-7+b3 libxslt1.1=1.1.32-2.2~deb10u1 libnginx-mod-http-dav-ext=1.14.2-2+deb10u1 libnginx-mod-http-echo=1.14.2-2+deb10u1 libnginx-mod-http-geoip=1.14.2-2+deb10u1 libnginx-mod-http-image-filter=1.14.2-2+deb10u1 libnginx-mod-http-subs-filter=1.14.2-2+deb10u1 libnginx-mod-http-upstream-fair=1.14.2-2+deb10u1 libnginx-mod-http-xslt-filter=1.14.2-2+deb10u1 libnginx-mod-mail=1.14.2-2+deb10u1 libnginx-mod-stream=1.14.2-2+deb10u1 libpython3.7=3.7.3-2+deb10u1 libpython3.7-dev=3.7.3-2+deb10u1 libpython3-dev=3.7.3-1 libsasl2-modules=2.1.27+dfsg-1+deb10u1 libssl-dev=1.1.1d-0+deb10u2 libtasn1-doc=4.13-3 libutempter0=1.1.6-3 manpages-dev=4.16-2 netcat=1.10-41.1 nginx-full=1.14.2-2+deb10u1 nginx=1.14.2-2+deb10u1 publicsuffix=20190415.1030-1 python3.7-dev=3.7.3-2+deb10u1 python3-dev=3.7.3-1 screen=4.6.2-3


RUN adduser --system --no-create-home --disabled-login nginx
RUN mkdir /etc/ssl/celery_client
RUN mkdir /portal
COPY portal /portal/
RUN mkdir /portal/nvd
RUN mkdir /portal/nvd/cache
RUN mkdir /portal/nvd/download
RUN mkdir /portal/nvd/feeds
RUN mkdir /portal/logs/
RUN touch /portal/logs/django.log
RUN touch /portal/logs/celery.log
WORKDIR /portal

COPY /portal/conf/site.conf /etc/nginx/sites-enabled/pulsar

RUN chmod a+x /portal/conf/gunicorn.sh

RUN chown -R nginx:nogroup /portal/

RUN pip install --upgrade pip && pip install -r requirements.txt
