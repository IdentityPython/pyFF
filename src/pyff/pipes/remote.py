__author__ = 'leifj'

def run(md,t,name,args,id):
    for d in args:
        if type(d) is dict and d.has_key('url'):
            md.load_url(**d)
    return t