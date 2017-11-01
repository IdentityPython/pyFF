from __future__ import print_function
__author__ = 'leifj'
# -*- coding: utf-8 -*-

import os
import gettext
import cherrypy

LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "i18n")


def _get_language():
    languages = [x.value.replace('-', '_') for x in cherrypy.request.headers.elements('Accept-Language')]
    language = gettext.translation('messages', LOCALE_DIR, languages, fallback=True)

    return language


def ugettext(*args, **kwargs):
    return _get_language().ugettext(*args, **kwargs)


def ngettext(*args, **kwargs):
    return _get_language().ngettext(*args, **kwargs)
