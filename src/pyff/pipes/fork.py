from pyff.pipes import Plumbing

__author__ = 'leifj'

from copy import deepcopy

def run(md,t,name,args,id):
    """
    Make a copy of the working tree and process the arguments as a pipleline
    """
    if type(args) is str or type(args) is unicode:
        args = [args]
    nt = None
    if t is not None:
        nt = deepcopy(t)

    Plumbing(pipeline=args,id=id).process(md)



