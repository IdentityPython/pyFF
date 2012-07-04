from pyff.mdrepo import NS

__author__ = 'leifj'

def run(ts,t,**kwargs):
    for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        print e.get('entityID')
    return t