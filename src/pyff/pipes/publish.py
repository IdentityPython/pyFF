import os
from lxml import etree
from pyff.utils import dumptree

__author__ = 'leifj'

def run(md,t,name,args,id):
    """
    Publish the working tree.
    """
    output_file = args.get("output",None)
    if output_file is not None:
        out = output_file
        if os.path.isdir(output_file):
            out = "%s.xml" % os.path.join(output_file,id)
        with open(out,"w") as fo:
            fo.write(dumptree(t))
    return t