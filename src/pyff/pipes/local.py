__author__ = 'leifj'

import os

def run(md,t,name,args,id):
    for d in args:
        if os.path.isdir(d):
            md.load_dir(d)
    return t