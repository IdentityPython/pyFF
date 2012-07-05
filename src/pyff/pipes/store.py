import os
import hashlib
from lxml import etree
from pyff.mdrepo import NS

__author__ = 'leifj'

def run(md,t,name,args,id):
    """
    Split into EntityDescriptor-parts and save in directory/sha1(@entityID).xml
    """
    target_dir = args.pop('directory',None)
    if target_dir is not None:
        if not os.path.isdir(target_dir):
            os.makedirs(target_dir)
        if t is None:
            raise Exception,"Your plumbing is missing a select statement."
        for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
            eid = e.get('entityID')
            if eid is None or len(eid) == 0:
                raise Exception,"Missing entityID in %s" % e
            m = hashlib.sha1()
            m.update(eid)
            d = m.hexdigest()
            with open("%s.xml" % os.path.join(target_dir,d),"w") as fn:
                fn.write(etree.tostring(e,encoding='UTF-8',xml_declaration=True,pretty_print=True))
    return t

