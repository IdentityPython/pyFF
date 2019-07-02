
import logging
import subprocess
import sys
import tempfile
from unittest import TestCase
import os
import pkg_resources
import six
import socket
import random

from pyff import __version__ as pyffversion

# range of ports where available ports can be found
PORT_RANGE = [33000, 60000]
MAX_PORT_TRIES = 100


class ExitException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "would have exited with %d" % self.code


def find_unbound_port(i=0):
    """
    Returns an unbound port number on 127.0.0.1.
    """
    if i > MAX_PORT_TRIES:
        raise ValueError("Unable to find an unused port after %d tries" % i)
    port = random.randint(*PORT_RANGE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except socket.error:
        port = find_unbound_port(i + 1)
    return port


def run_pyff(*args):
    return run_cmdline('pyff', args)


def run_pyffd(*args):
    return run_cmdline('pyffd', args)


def run_cmdline(script, *args):
    argv = list(*args)
    starter = tempfile.NamedTemporaryFile('w').name
    print("starting %s using %s" % (script, starter))
    with open(starter, 'w') as fd:
        fd.write("""#!%s
import sys
import coverage
import os
from pkg_resources import load_entry_point
if __name__ == '__main__':
    cov = coverage.coverage(cover_pylib=False, source=['pyff'], omit=['test'])
    cov.start()
    rv = 0
    try:
        rv = load_entry_point('pyFF==%s', 'console_scripts', '%s')()
    except Exception as ex:
        raise ex
    finally:
        cov.stop()
        cov.save()
        os.rename('.coverage','.coverage.%%d' %% os.getpid())
    sys.exit(rv)

""" % (sys.executable, pyffversion, script))
    os.chmod(starter, 0o700)

    argv.insert(0, starter)
    proc = _pstart(argv)
    out, err = proc.communicate()
    rv = proc.wait()
    os.unlink(starter)
    if isinstance(out, six.binary_type):
        out = out.decode('utf-8')
    if isinstance(err, six.binary_type):
        err = err.decode('utf-8')

    print(">> STDOUT ---")
    print(out)
    print(">> STDERR ---")
    print(err)
    print("rv=%d" % rv)
    print("<< EOF")

    return out, err, rv


def _pstart(args, outf=None, ignore_exit=False):
    env = {}
    logging.debug(" ".join(args))
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    return proc


def _p(args, outf=None, ignore_exit=False):
    proc = _pstart(args)
    out, err = proc.communicate()
    if err is not None and len(err) > 0:
        logging.error(err)
    if outf is not None:
        with open(outf, "w") as fd:
            fd.write(out.decode('UTF-8'))
    else:
        if out is not None and len(out) > 0:
            logging.debug(out.decode('UTF-8'))
    rv = proc.wait()
    if rv and not ignore_exit:
        raise RuntimeError("command exited with code != 0: %d" % rv)


class SignerTestCase(TestCase):

    datadir = None
    private_keyspec = None
    public_keyspec = None

    def sys_exit(self, code):
        raise ExitException(code)

    @classmethod
    def setUpClass(cls):
        cls.datadir = pkg_resources.resource_filename(__name__, 'data')
        cls.private_keyspec = tempfile.NamedTemporaryFile('w').name
        cls.public_keyspec = tempfile.NamedTemporaryFile('w').name

        _p(['openssl', 'genrsa',
            '2048',
            '-nodes'], outf=cls.private_keyspec, ignore_exit=True)
        _p(['openssl', 'req',
            '-x509',
            '-sha1',
            '-new',
            '-subj', '/CN=Signer',
            '-key', cls.private_keyspec,
            '-out', cls.public_keyspec])

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.private_keyspec):
            os.unlink(cls.private_keyspec)
        if os.path.exists(cls.public_keyspec):
            os.unlink(cls.public_keyspec)