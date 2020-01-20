#!/bin/bash

pipeline=${1:-examples/mdx.fd}; shift


exec gunicorn --reload --reload-extra-file ${pipeline} --preload --log-config ${PYFF_LOGGER:-examples/debug.ini} --bind 0.0.0.0:8080 -t 600 -e PYFF_PIPELINE=${pipeline} -e PYFF_STORE_CLASS=pyff.store:RedisWhooshStore -e PYFF_UPDATE_FREQUENCY=300 --threads 4 --worker-tmp-dir=/dev/shm --worker-class=gthread pyff.wsgi:app
