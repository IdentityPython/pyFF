from pyff.mdrepo import NS

__author__ = 'leifj'

def run(md,t,name,args,id):
    print "---"
    print "total size:     %d" % len(md.keys())
    if t is not None:
        print "selected:       %d" % len(t.xpath("//md:EntityDescriptor",namespaces=NS))
        print "          idps: %d" % len(t.xpath("//md:EntityDescriptor[md:IDPSSODescriptor]",namespaces=NS))
        print "           sps: %d" % len(t.xpath("//md:EntityDescriptor[md:SPSSODescriptor]",namespaces=NS))
    print "---"