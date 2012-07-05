__author__ = 'leifj'

from copy import deepcopy

def run(md,t,name,args,id):
    """
    Make a copy of the working tree and process the arguments as a pipleline
    """
    nt = None
    if t is not None:
        nt = deepcopy(t)


