from pyff.mdrepo import NS

__author__ = 'leifj'

def run(md,t,name,args,id):
    print "total size: %d" % len(md.keys())
    print "selected: %d" % len(t.xpath("//md:EntityDescriptor",namespaces=NS))