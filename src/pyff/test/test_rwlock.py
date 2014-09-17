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

    def test_error_on_release_unheld_lock(self):
        try:
            self.lock.release()
            assert False
        except ValueError:
            pass

    def timeout_writer(self, timeout=1):
        try:
            self.lock.acquireWrite(timeout=timeout)
            print "thread (writer): %s starting" % current_thread().name
            self.writer_active = True
            sleep(1)
        except Exception, ex:
            self.exceptions[current_thread().name] = ex
        finally:
            try:
                self.lock.release()
            except ValueError:  # ignore double release error
                pass

        self.writer_active = False
        print "thread: %s exiting" % current_thread().name

    def timeout_reader(self, to_wait_for, timeout=1):
        try:
            self.lock.acquireRead(timeout=timeout)
            assert(not self.writer_active)
            print "thread (reader): %s starting" % current_thread().name
            self.readers += 1
            while to_wait_for - self.readers > 0:
                assert(not self.writer_active)
                print "waiting for %d more readers" % (to_wait_for - self.readers)
                sleep(0.1)
        except Exception, ex:
            self.exceptions[current_thread().name] = ex
        finally:
            try:
                self.lock.release()
            except ValueError:  # ignore double release error
                pass

        print "thread (reader): %s exiting" % current_thread().name

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

    def test_2_readers_and_3_writers(self):
        w1 = Thread(target=self.writer, name="w1")
        w2 = Thread(target=self.writer, name="w2")
        w3 = Thread(target=self.timeout_writer, name="w3", args=[0.01])
        r1 = Thread(target=self.reader, name="r1", args=[2])
        r2 = Thread(target=self.reader, name="r2", args=[2])
        w1.start()
        r1.start()
        w2.start()
        w3.start()
        r2.start()
        w1.join(timeout=60)
        self._raise(w1)
        r1.join(timeout=60)
        self._raise(r1)
        r2.join(timeout=60)
        self._raise(r2)
        w2.join(timeout=60)
        w3.join(timeout=60)
        try:
            self._raise(w3)
            assert False
        except ValueError:
            pass
        except RuntimeError:
            pass