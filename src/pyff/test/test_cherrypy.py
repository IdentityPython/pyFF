import logging
from unittest import TestCase


class TestStats(TestCase):

    def test_stats(self):
        from pyff.stats import stats
        assert(hasattr(logging,'statistics'))
        assert('pyFF Statistics' in logging.statistics)
        assert(stats['Enabled'])
        assert(stats['Repository Size'] == 0)