from pyff.mdrepo import NS

__author__ = 'leifj'

def run(md,t,name,args,id):
    if t is None:
        raise Exception,"Your plumbing is missing a select statement."

    for e in t.xpath("//md:EntityDescriptor",namespaces=NS):
        print e.get('entityID')
    return t