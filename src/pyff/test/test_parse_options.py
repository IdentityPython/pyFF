import sys

from unittest import TestCase
from unittest.mock import patch

from pyff.constants import parse_options, config


class TestParseOptions(TestCase):

    def test_bool_long_spec_setting(self):
        test_args = ["pyffd", "--devel_memory_profile", "--foreground"]

        with patch.object(sys, 'argv', test_args):
            parse_options("pyffd", "Additional help.")

        self.assertTrue(config.devel_memory_profile)
        self.assertTrue(config.foreground)
        self.assertFalse(config.daemonize)

    def test_inverted_setting_short_spec(self):
        test_args = ["pyffd", "-C"]

        with patch.object(sys, 'argv', test_args):
            parse_options("pyffd", "Additional help.")

        self.assertTrue(config.no_caching)
        self.assertFalse(config.caching_enabled)
