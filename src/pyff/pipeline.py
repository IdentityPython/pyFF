__author__ = 'leifj'

class PipeLoader(object):
    def load_pipe(self,d):
        if not type(d) is dict:
            raise Exception,"This does not look like a length of pipe... \n%s" % repr(d)
        name = d.pop('name',None)
        if name is None:
            raise Exception,"Anonymous length of pipe... \n%s" % repr(d)


loader = PipeLoader()