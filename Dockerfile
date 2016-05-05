# A standard build environment for pyFF
FROM ubuntu:14.04
MAINTAINER Leif Johansson <leifj@mnt.se>
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt-get -q update
RUN apt-get -y upgrade
RUN apt-get install -y git-core swig libyaml-dev libyaml-dev python-dev build-essential libxml2-dev libxslt-dev libz-dev python-virtualenv wget
RUN pip install --upgrade git+git://github.com/leifj/pyXMLSecurity.git#egg=pyXMLSecurity
