from pyff.utils import resource_string
from lxml import etree

__author__ = 'leifj'

def run(md,t,name,args,id):
    """
    Apply an XSLT stylesheet
    """
    stylesheet = args.pop('stylesheet',None)
    if stylesheet is not None:
        if t is None:
            raise Exception,"Your plumbing is missing a select statement."
        xslt = etree.fromstring(resource_string(stylesheet,"xslt"))
        transform = etree.XSLT(xslt)
        # this is to make sure the parameters are passed as xslt strings
        d = dict((k,"\'%s\'" % v) for (k,v) in args.items())
        ot = transform(t,**d)
        t = ot
    return t