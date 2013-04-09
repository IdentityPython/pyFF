"""

Cherrypy statistics module

"""

import time
import logging

__author__ = 'leifj'

# Initialize the repository
if not hasattr(logging, 'statistics'): logging.statistics = {}
# Initialize my namespace
stats = logging.statistics.setdefault('pyFF Statistics', {})
# Initialize my namespaces scalars and collections
stats.update({
    'Enabled': True,
    'Start Time': time.time(),
    'MD Requests': 0,
    'Repository Update Time': None,
    'Repository Size': 0,
    'Requests/Second': lambda s: (
        (s['MD Requests'] / (time.time() - s['Start Time']))),
})

