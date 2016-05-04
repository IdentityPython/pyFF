#!/bin/bash

dst=$1

if [ "x$dst" = "x" ]; then
   dst=/opt/pyff
fi

mkdir -p $dst

apt-get install python-dev build-essential libxml2-dev libxslt-dev python-virtualenv libyaml-dev

virtualenv $dst
. $dst/bin/activate
pip install pyff
