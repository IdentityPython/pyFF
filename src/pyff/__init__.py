"""
pyFF is a SAML metadata aggregator.
"""

import pkg_resources
from . import builtins

__author__ = 'Leif Johansson'
__copyright__ = "Copyright 2009-2014 SUNET"
__license__ = "BSD"
__maintainer__ = "leifj@sunet.se"
__status__ = "Production"
# removing following line was a quick fix to thes message "pkg_resources.DistributionNotFound: The 'pyFF' distribution was not found"
#__version__ = pkg_resources.require("pyFF")[0].version
