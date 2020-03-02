#!/bin/bash

NAME="portal"                              #Name of the application (*)
DJANGODIR=/portal             # Django project directory (*)
SOCKFILE=/tmp/run/gunicorn.sock        # we will communicate using this unix socket (*)
USER=nginx                                        # the user to run as (*)
GROUP=webdata                                     # the group to run as (*)
NUM_WORKERS=1                                     # how many worker processes should Gunicorn spawn (*)
DJANGO_SETTINGS_MODULE=portal.settings             # which settings file should Django use (*)
DJANGO_WSGI_MODULE=portal.wsgi                     # WSGI module name (*)

# Activate the virtual environment
cd /portal
export DJANGO_SETTINGS_MODULE=portal.settings
export D_SECRET_KEY=$(openssl rand -base64 128)

# Create the run directory if it doesn't exist
RUNDIR=/portal/run
test -d /tmp/run || mkdir -p /tmp/run

# Start gunicorn
gunicorn portal.wsgi:application --name portal --workers 1 --user nginx --bind=unix:/tmp/run/gunicorn.sock -t 600
