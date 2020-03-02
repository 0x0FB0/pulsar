FROM python:3.8.2-slim-buster
ENV PYTHONUNBUFFERED 1

COPY secrets_storage/sandbox_key /etc/ssh/sandbox_key
RUN chmod 0600 /etc/ssh/sandbox_key

RUN apt-get update && apt-get install -y nginx python3-dev apache2-utils libexpat1 netcat less screen \
 openssl libmariadb-dev libcurl4-openssl-dev libssl-dev gcc

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
