__author__ = 'leifj'

def run(md,t,name,args,id):
    """
    Return a signed tree
    """
    if t is None:
        raise Exception,"Your plumbing is missing a select statement."
    return t