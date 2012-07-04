from UserDict import DictMixin
from pyff.utils import resource_string, dmerge

__author__ = 'leifj'

import yaml

class Feed(DictMixin):
    def __init__(self):
        self.seen = []
        self.config = {}

    def parse(self,fn):
        ystr = resource_string(fn,"feeds")
        if ystr is not None:
            d = yaml.safe_load(ystr)
            if d is not None:
                #feed.update(d)
                dmerge(self.config,d)
            # not to be confused with a real inheritance mechanism
        self.seen.append(fn)
        for ext in self.config.get('extends',[]):
            if not ext in self.seen:
                self.parse(ext)
        return self

    def __getitem__(self, item):
        return self.config.get(item)

    def __setitem__(self, key, value):
        self.config[key] = value

    def __delitem__(self, key):
        del self.config[key]

    def keys(self):
        return self.config.keys()

def import_feed(fn):
    return Feed().parse(fn)
