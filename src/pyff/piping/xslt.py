from pyff import resource_string
from lxml import etree

__author__ = 'leifj'

def run(ts,t,**kwargs):
    """
    Apply an XSLT stylesheet
    """
    stylesheet = ts.pop('stylesheet',None)
    if stylesheet is not None:
        xslt = etree.parse(resource_string(stylesheet,"xslt"))
        transform = etree.XSLT(xslt)
        # this is to make sure the parameters are passed as xslt strings
        d = dict((k,"\'%s\'" % v) for (k,v) in ts.items())
        ot = transform(t,**d)
        t = ot
    return t