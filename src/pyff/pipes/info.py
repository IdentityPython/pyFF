from pyff.mdrepo import NS

__author__ = 'leifj'

def run(md,t,name,args,id):
    for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        print e.get('entityID')
    return t