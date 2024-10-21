import queue
import threading
from datetime import datetime

from pyff.constants import config
from pyff.logs import get_log
from pyff.utils import Watchable, load_callable, url_get

log = get_log(__name__)


def make_resourcestore_instance(*args, **kwargs):
    new_store = load_callable(config.resource_store_class)
    return new_store(*args, **kwargs)


class ResourceStore(object):
    pass


class Fetch(threading.Thread):
    """
    Fetch is a thread that calls url_get to retrieve a URL. All URL schemes supported by the python requests
    library aswell as file:/// URLs are supported. The Fetch thread is part of a thread pool that works off of
    a deque feed by a main Fetcher thread. Results are passed back via another deque owned by the Fetcher. A
    content handler callable is called with the response object and the result is passed up to the Fetcher.
    """

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
        self.name = "{} ({})".format(self._id, state)

    def run(self):
        while not self.halt:
            log.debug("waiting for pool {}....".format(self._id))
            with self.pool:
                url = self.request.get()
                if url is not None:
                    try:
                        self.state(url)
                        r = url_get(url,verify_tls=False)
                        if self.content_handler is not None:
                            r = self.content_handler(r)
                        self.response.put(
                            {'response': r, 'url': url, 'exception': None, 'last_fetched': datetime.now()}
                        )
                        log.debug("successfully fetched {}".format(url))
                    except Exception as ex:
                        self.response.put(
                            {'response': None, 'url': url, 'exception': ex, 'last_fetched': datetime.now()}
                        )
                        log.warning("error fetching {}".format(url))
                        log.warning(ex)
                        import traceback

                        log.debug(traceback.format_exc())
                    finally:
                        self.state('idle')
                self.request.task_done()


class Fetcher(threading.Thread, Watchable):
    """
    The main threed managing a pool of Fetch threads. All Fetch instances are initiatlized with the same
    content handler callable.
    """

    def __init__(self, num_threads=config.worker_pool_size, name="Fetcher", content_handler=None):
        threading.Thread.__init__(self)
        Watchable.__init__(self)
        self._id = name
        self.name = '{} (master)'.format(self._id)
        self.request = queue.Queue()
        self.response = queue.Queue()
        self.pool = threading.BoundedSemaphore(num_threads)
        self.threads = []
        for i in range(0, num_threads):
            t = Fetch(self.request, self.response, self.pool, self._id, content_handler)
            t.start()
            self.threads.append(t)
        self.halt = False

    def schedule(self, url):
        """
        Schedule a URL for retrieval.

        :param url: the url to fetch
        :return: nothing is returned.
        """
        log.info("scheduling fetch of {}".format(url))
        self.request.put(url)

    def stop(self):
        """
        Halt the Fetcher and all Fetch threads.
        :return:
        """
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
        """
        Launch the Fetcher. Notify all watchers.

        :return:  nothing is returned
        """
        log.debug("Fetcher ({}) ready & waiting for responses...".format(self._id))
        while not self.halt:
            info = self.response.get()
            if info is not None:
                self.notify(**info)
        log.debug("Fetcher ({}) exiting...".format(self._id))


def make_fetcher(name="Fetcher", content_handler=None):
    """
    A utility method that creates and starts a Fetcher with the specified content handler.

    :param name: A name - used in displays and instrumentation
    :param content_handler: a callable - passed to the main Fetcher thread
    :return: the Fetcher instance in running state
    """
    f = Fetcher(name=name, content_handler=content_handler)
    f.start()
    log.debug("fetcher created: {}".format(f))
    return f
