from pyff.utils import dumptree
from pyff.mdrepo import NS

__author__ = 'leifj'


def run(md,t,name,args,id):
    if t is not None:
        print dumptree(t)
    else:
        print "<EntitiesDescriptor xmlns=\"%s\"/>" % NS['md']