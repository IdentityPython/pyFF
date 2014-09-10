from threading import Thread, current_thread
from time import sleep
from unittest import TestCase
from pyff.locks import ReadWriteLock


class TestReadWriteLock(TestCase):
    def setUp(self):
        self.lock = ReadWriteLock()
        self.readers = 0
        self.writer_active = False
        self.exceptions = dict()

    def writer(self):
        try:
            with self.lock.writelock:
                print "thread (writer): %s starting" % current_thread().name
                self.writer_active = True
                sleep(1)
                self.writer_active = False
            print "thread: %s exiting" % current_thread().name
        except Exception, ex:
            self.exceptions[current_thread().name] = ex

    def reader(self, to_wait_for):
        try:
            with self.lock.readlock:
                assert(not self.writer_active)
                print "thread (reader): %s starting" % current_thread().name
                self.readers += 1
                while to_wait_for - self.readers > 0:
                    assert(not self.writer_active)
                    print "waiting for %d more readers" % (to_wait_for - self.readers)
                    sleep(0.1)
            print "thread (reader): %s exiting" % current_thread().name
        except Exception, ex:
            self.exceptions[current_thread().name] = ex

    def _raise(self, t):
        assert (not t.isAlive())
        if t.name in self.exceptions:
            raise self.exceptions[t.name]

    def test_2_readers(self):
        w1 = Thread(target=self.writer, name="w1")
        w2 = Thread(target=self.writer, name="w2")
        r1 = Thread(target=self.reader, name="r1", args=[2])
        r2 = Thread(target=self.reader, name="r2", args=[2])
        w1.start()
        r1.start()
        w2.start()
        r2.start()
        w1.join(timeout=60)
        self._raise(w1)
        r1.join(timeout=60)
        self._raise(r1)
        r2.join(timeout=60)
        self._raise(r2)
        w2.join(timeout=60)