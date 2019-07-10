
from .logs import get_log
import queue
import threading
from datetime import datetime
from .utils import url_get, load_callable, Watchable
from .constants import config

log = get_log(__name__)


def make_resourcestore_instance(*args, **kwargs):
    new_store = load_callable(config.resource_store_class)
    return new_store(*args, **kwargs)


class ResourceStore(object):
    pass


class Fetch(threading.Thread):

    def __init__(self, request, response, pool, name, content_handler):
        threading.Thread.__init__(self)
        self._id = name
        self.request = request
        self.response = response
        self.pool = pool
        self.halt = False
        self.content_handler = content_handler
        self.state('idle')

    def state(self, state):
        self.setName("{} ({})".format(self._id, state))

    def run(self):
        while not self.halt:
            log.debug("waiting for pool {}....".format(self._id))
            with self.pool:
                url = self.request.get()
                if url is not None:
                    try:
                        self.state(url)
                        r = url_get(url)
                        if self.content_handler is not None:
                            r = self.content_handler(r)
                        self.response.put({'response': r, 'url': url, 'exception': None, 'last_fetched': datetime.now()})
                    except Exception as ex:
                        self.response.put({'response': None, 'url': url, 'exception': ex, 'last_fetched': datetime.now()})
                        import traceback
                        log.debug(traceback.format_exc())
                        log.warn(ex)
                    finally:
                        self.state('idle')
                self.request.task_done()


class Fetcher(threading.Thread, Watchable):

    def __init__(self, num_threads=config.worker_pool_size, name="Fetcher", content_handler=None):
        threading.Thread.__init__(self)
        Watchable.__init__(self)
        self._id = name
        self.setName('{} (master)'.format(self._id))
        self.request = queue.Queue()
        self.response = queue.Queue()
        self.pool = threading.BoundedSemaphore(num_threads)
        self.threads = []
        for i in range(0,num_threads):
            t = Fetch(self.request, self.response, self.pool, self._id, content_handler)
            t.start()
            self.threads.append(t)
        self.halt = False

    def schedule(self, url):
        log.debug("putting {} on queue".format(url))
        self.request.put(url)

    def stop(self):
        log.debug("stopping fetcher")
        for t in self.threads:
            t.halt = True
        for t in self.threads:
            self.request.put(None)
        for t in self.threads:
            t.join()
        self.halt = True
        self.response.put(None)

    def run(self):
        log.debug("Fetcher ({}) ready & waiting for responses...".format(self._id))
        while not self.halt:
            info = self.response.get()
            if info is not None:
                self.notify(**info)
        log.debug("Fetcher ({}) exiting...".format(self._id))


def make_fetcher(name="Fetcher", content_handler=None):
    f = Fetcher(name=name, content_handler=content_handler)
    f.start()
    log.debug("fetcher created: {}".format(f))
    return f
