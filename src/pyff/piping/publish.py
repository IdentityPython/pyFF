import os
from lxml import etree

__author__ = 'leifj'

def run(ts,t,**kwargs):
    """
    Publish the tree
    """
    feed = kwargs['feed']
    output_file = ts.get("output",None)
    if output_file is not None:
        out = output_file
        if os.path.isdir(output_file):
            out = "%s.xml" % os.path.join(output_file,feed.id)
        with open(out,"w") as fo:
            fo.write(etree.tostring(t,encoding='UTF-8',xml_declaration=True,pretty_print=True))
    return t