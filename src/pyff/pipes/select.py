__author__ = 'leifj'

def run(md,t,name,args,id):
    if args is None:
        args = md.keys()
    return md.entity_set(args,id)