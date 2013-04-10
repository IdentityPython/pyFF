import logging
import os
import subprocess
import tempfile
from unittest import TestCase
import pkg_resources

__author__ = 'leifj'


def _p(args, outf=None, ignore_exit=False):
    env = {}
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    logging.debug(" ".join(args))
    out, err = proc.communicate()
    if err is not None and len(err) > 0:
        logging.error(err)
    if outf is not None:
        with open(outf, "w") as fd:
            fd.write(out)
    else:
        if out is not None and len(out) > 0:
            logging.debug(out)
    rv = proc.wait()
    if rv and not ignore_exit:
        raise RuntimeError("command exited with code != 0: %d" % rv)


class SignerTestCase(TestCase):

    def setUp(self):
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.private_keyspec = tempfile.NamedTemporaryFile('w').name
        self.public_keyspec = tempfile.NamedTemporaryFile('w').name

        _p(['openssl', 'genrsa',
            '2048',
            '-nodes'], outf=self.private_keyspec, ignore_exit=True)
        _p(['openssl', 'req',
            '-x509',
            '-sha1',
            '-new',
            '-subj', '/CN=Signer',
            '-key', self.private_keyspec,
            '-out', self.public_keyspec])

    def tearDown(self):
        if os.path.exists(self.private_keyspec):
            os.unlink(self.private_keyspec)
        if os.path.exists(self.public_keyspec):
            os.unlink(self.public_keyspec)
