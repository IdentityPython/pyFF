__author__ = 'leifj'
# -*- coding: utf-8 -*-

import gettext
import cherrypy
import locale
import os
import six

# Change this variable to your app name!
#  The translation files will be under
#  @LOCALE_DIR@/@LANGUAGE@/LC_MESSAGES/@APP_NAME@.mo
APP_NAME = "pyFF"

# This is ok for maemo. Not sure in a regular desktop:
LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "i18n")

languages = [x.value.replace('-', '_') for x in cherrypy.request.headers.elements('Accept-Language')]
languages += ['en_US']

lc, encoding = locale.getdefaultlocale()
if lc:
    languages += [lc]

mo_location = LOCALE_DIR

if six.PY2:
    gettext.install(True, localedir=None, unicode=1)
else:
    gettext.install(True, localedir=None)

gettext.find(APP_NAME, mo_location)
gettext.textdomain(APP_NAME)
gettext.bind_textdomain_codeset(APP_NAME, "UTF-8")
language = gettext.translation(APP_NAME, mo_location, languages=languages, fallback=True)
