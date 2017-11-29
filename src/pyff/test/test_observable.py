from unittest import TestCase

from pyff.mdrepo import Observable
from pyff.utils import debug_observer


class TestObservable(TestCase):

    class Foo(Observable):
        def __init__(self, done=False):
            super(TestObservable.Foo, self).__init__()
            self.done = done


    def test_create_observable(self):
        o = TestObservable.Foo()
        assert(o is not None)
        assert(isinstance(o, Observable))

    def test_observe(self):

        def _cb(event):
            assert('a' in event)
            assert('b' not in event)
            assert('myself' in event)
            assert(event['a'] == 1)
            assert(not event['myself'].done)
            event['myself'].done = True

        o = TestObservable.Foo()
        o.subscribe(_cb)
        o.subscribe(debug_observer)
        o.event(a=1, myself=o)
        assert o.done