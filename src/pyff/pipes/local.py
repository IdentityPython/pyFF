__author__ = 'leifj'

import os

def run(md,t,name,args,id):
    if type(args) is str or type(d) is unicode:
        args = [args]
    for d in args:
        if os.path.isdir(d):
            md.load_dir(d)
    return t