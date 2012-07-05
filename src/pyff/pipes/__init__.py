import os
import yaml
from pyff.utils import resource_string

__author__ = 'leifj'

class PipeLoader(object):

    def load_pipe(self,d):
        if not type(d) is dict:
            raise Exception,"This does not look like a length of pipe... \n%s" % repr(d)
        name = d.keys()[0]
        if name is None:
            raise Exception,"Anonymous length of pipe... \n%s" % repr(d)

        return __import__("pyff.pipes.%s" % name, fromlist=["pyff.pipes"]),name,d[name]

class Plumbing(object):
    """
    A plumbing instance represents a basic processing chaing for SAML metadata.

    A basic example:

    - local:
       - /var/metadata/registry

    - select:
       - #md:EntityDescriptor[md:IDPSSODescriptor]

    - xslt:
        stylesheet: tidy.xsl

    - xslt:
        stylesheet: pp.xsl

    - fork:

       - xslt:
           stylesheet: publish.xsl
           Name: http://example.com/metadata.xml
           cacheDuration: PT1H
           validUntil: 30d

        - sign:
           key: signer.key
           cert: signer.crt

       - publish:
           output: /var/metadata/public/metadata.xml

    Running this pipeline would bake all metadata found in /var/metadata/registry
    into an EntitiesDescriptor element with @Name http://example.com/metadata.xml,
    cacheDuration 1hr, validUntil 1 day from now. The tree woud be transformed
    using the "tidy" and "pp" (for pretty-print) stylesheets and would then be
    signed (using signer.key) and finally published in /var/metadata/public/metadata.xml
    """
    def __init__(self,pipeline,id):
        self.id = id
        self.pipeline = pipeline

    def __iter__(self):
        return self.pipeline

    def process(self,md):
        t = None
        for p in self.pipeline:
            print p
            pipe,name,args = loader.load_pipe(p)
            t = pipe.run(md,t,name,args,self.id)
        return t

def plumbing(fn):
    id = os.path.splitext(fn)[0]
    ystr = resource_string(fn)
    pipeline = yaml.safe_load(ystr)

    return Plumbing(pipeline=pipeline,id=id)

loader = PipeLoader()