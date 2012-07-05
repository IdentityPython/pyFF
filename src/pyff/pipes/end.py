__author__ = 'leifj'

import sys

def run(md,t,name,args,id):
    """
    Exit with optional error code and message
    """
    code = 0
    if args is not None:
        code = args.get('code',0)
        msg = args.get('message',None)
        if msg is None:
            print msg
    sys.exit(code)