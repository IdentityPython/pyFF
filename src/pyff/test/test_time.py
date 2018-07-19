from datetime import datetime
from unittest import TestCase

from pyff.utils import duration2timedelta, total_seconds, iso_now, iso2datetime, iso_fmt, totimestamp


class TestDuration(TestCase):

    DURATIONS = [
        ('PT1H', 3600),
        ('PT1S', 1),
        ('P1DT1S', 86401),
        ('P1YT2M', 31536120),
        ('-PT1H', -3600)
    ]

    def test_duration2timedelta(self):
        for expr, secs in TestDuration.DURATIONS:
            td = duration2timedelta(expr)
            print("timedelta: %s" % td)
            print("duration: %s" % expr)
            print("expected seconds: %s" % secs)
            assert(int(td.total_seconds()) == secs)
            assert(int(total_seconds(td)) == secs)

    def test_bad(self):
        assert (duration2timedelta("abrakadabra") is None)


class TestISO(TestCase):

    def test_isonow(self):
        now = iso_now()
        assert(now is not None)
        assert(now.endswith('Z'))

    def test_iso2datetime(self):
        now = datetime.now()
        now = now.replace(tzinfo=None)
        iso = iso_fmt(totimestamp(now))
        other_now = iso2datetime(iso)
        other_now = other_now.replace(tzinfo=None)
        assert ((other_now - now).total_seconds() < 0.1)
