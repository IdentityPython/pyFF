__author__ = 'leifj'

def run(md,t,name,args,id):
    if args is None:
        args = md.keys()
    if type(args) is str or type(args) is unicode:
        args = [args]
    return md.entity_set(args,id)