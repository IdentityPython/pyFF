__author__ = 'leifj'

def run(md,t,name,args,id):
    for d in args:
        if type(d) is str or type(d) is unicode:
            lst = d.split()
            d = None
            if len(lst) == 1:
                d = {'url':lst[0]}
            elif len(lst) > 1:
                d = {'url': lst[0],'verify': lst[1]}
            if d is not None:
                md.load_url(**d)
        elif type(d) is dict and d.has_key('url'):
            md.load_url(**d)
    return t