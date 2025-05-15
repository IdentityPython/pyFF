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

    def reset(self):
        self.exceptions = dict()

    def test_error_on_release_unheld_lock(self):
        try:
            self.lock.release()
            assert False
        except ValueError:
            pass

    def timeout_writer(self, timeout=1):
        try:
            for tries in range(1, 10):
                self.lock.acquireRead(timeout=timeout, blocking=False)  # get a read
            for tries in range(1, 10):
                self.lock.acquireWrite(timeout=timeout, blocking=False)  # upgrade to write

            self.lock.acquireWrite(blocking=True)  # get it twice...
            print(f"thread (writer): {current_thread().name} starting")
            self.writer_active = True
            sleep(1)
        except Exception as ex:
            self.exceptions[current_thread().name] = ex
        finally:
            try:
                self.lock.release()
            except ValueError:  # ignore double release error
                pass

        self.writer_active = False
        print(f"thread: {current_thread().name} exiting")

    def timeout_reader(self, to_wait_for, timeout=1):
        try:
            self.lock.acquireRead(timeout=timeout)
            assert not self.writer_active
            print(f"thread (reader): {current_thread().name} starting")
            self.readers += 1
            while to_wait_for - self.readers > 0:
                assert not self.writer_active
                print("waiting for %d more readers" % (to_wait_for - self.readers))
                sleep(0.1)
        except Exception as ex:
            self.exceptions[current_thread().name] = ex
        finally:
            try:
                self.lock.release()
            except ValueError:  # ignore double release error
                pass

        print(f"thread (reader): {current_thread().name} exiting")

    def writer(self):
        try:
            with self.lock.writelock:
                print(f"thread (writer): {current_thread().name} starting")
                self.writer_active = True
                self.lock.acquireRead(timeout=0.1)  # make sure we can get a readlock as a writer
                sleep(1)
                self.writer_active = False
            print(f"thread: {current_thread().name} exiting")
        except Exception as ex:
            self.exceptions[current_thread().name] = ex
        finally:
            try:
                self.lock.release()
            except ValueError:  # ignore double release error
                pass

    def reader(self, to_wait_for):
        try:
            with self.lock.readlock:
                assert not self.writer_active
                print(f"thread (reader): {current_thread().name} starting")
                self.readers += 1
                while to_wait_for - self.readers > 0:
                    assert not self.writer_active
                    print("waiting for %d more readers" % (to_wait_for - self.readers))
                    sleep(0.1)
            print(f"thread (reader): {current_thread().name} exiting")
        except Exception as ex:
            self.exceptions[current_thread().name] = ex

    def _raise(self, t):
        assert not t.is_alive()
        if t.name in self.exceptions:
            raise self.exceptions[t.name]

    def _rww(self, timeout=1, to_wait_for=2):
        try:
            self.lock.acquireRead(timeout=timeout)
            self.readers += 1
            while to_wait_for - self.readers > 0:
                pass
            self.lock.acquireWrite(timeout=timeout)
            self.lock.acquireWrite(timeout=timeout)
        except Exception as ex:
            self.exceptions[current_thread().name] = ex

    def test_unthreaded(self):
        try:
            self.lock.acquireRead(timeout=0.01)
            self.lock.acquireWrite(timeout=0.01)
            self.lock.acquireRead(timeout=0.01)
            self.lock.acquireWrite(timeout=0.01)
        except Exception as ex:
            raise ex
        finally:
            try:
                self.lock.release()
            except Exception:
                pass

    def test_deadlock(self):
        self.reset()
        try:
            w = []
            for i in range(10):
                w.append(Thread(target=self._rww, name=f"w{i}"))
            for i in range(10):
                w[i].start()
            for i in range(10):
                w[i].join()
            for i in range(10):
                self._raise(w[i])
            assert False
        except ValueError:
            pass

    def test_2_readers_and_3_writers(self):
        self.reset()
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
