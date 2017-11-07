from __future__ import print_function
__author__ = 'leifj'
# -*- coding: utf-8 -*-

import os
import gettext
import cherrypy

LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "i18n")


def _get_language(locales):
    language = gettext.translation('messages', LOCALE_DIR, locales, fallback=True)

    return language


def detect_locales():
    return [x.value.split('-')[0] for x in cherrypy.request.headers.elements('Accept-Language')]


def ugettext(*args, **kwargs):
    return _get_language(detect_locales()).ugettext(*args, **kwargs)


def ngettext(*args, **kwargs):
    return _get_language(detect_locales()).ngettext(*args, **kwargs)
