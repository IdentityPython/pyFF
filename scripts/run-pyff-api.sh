#!/bin/bash

pipeline=$1; shift

gunicorn --preload --log-config logger.ini --bind 0.0.0.0:8000 -t 600 -e PYFF_PIPELINE=$pipeline -e PYFF_STORE_CLASS=pyff.store:RedisWhooshStore -e PYFF_UPDATE_FREQUENCY=300 --threads 4 --worker-tmp-dir=/dev/shm --worker-class=gthread pyff.wsgi:app
