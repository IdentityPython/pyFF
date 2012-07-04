from UserDict import DictMixin
from pyff.utils import resource_string, dmerge
import os

__author__ = 'leifj'

import yaml

class Feed(DictMixin):
    """
    A feed represents a basic input->pipeline(->output) processing
    chaing for SAML metadata. A basic example:

    validUntil: 2d
    cacheDuration: PT1H
    Name: http://example.com/metadata.xml
    extends:
       - defaults
    inputs:
       - /var/metadata/registry
    pipeline:
        - name: xslt
          stylesheet: tidy
        - name: xslt
          stylesheet: pp
        - name: sign
          key: signer.key
          cert: signer.crt
        - name: publish
          output: /var/metadata/public/metadata.xml

    Running this pipeline would bake all metadata found in /var/metadata/registry
    into an EntitiesDescriptor element with @Name http://example.com/metadata.xml,
    cacheDuration 1hr, validUntil 1 day from now. The tree woud be transformed
    using the "tidy" and "pp" (for pretty-print) stylesheets and would then be
    signed (using signer.key) and finally published in /var/metadata/public/metadata.xml
    """
    def __init__(self):
        self.seen = []
        self.config = {}
        self.id = None

    def parse(self,fn):
        """
        Parse a feed from yaml. The parse method supports a basic form of
        pseudo-inheritance using the 'extends' key. Each feed listed in
        the extends list is parsed and deep-merged into this feed. The
        parse method returns the feed.
        """
        if self.id is None:
            self.id = os.path.splitext(fn)[0]
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
