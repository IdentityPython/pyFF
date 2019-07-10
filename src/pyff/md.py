"""
pyFF is the SAML metadata aggregator

Usage: [-h|--help]
       [-R]
       [--loglevel=<level>]
       [--logfile=<file>]
       [--version]
"""
import importlib
import logging
import sys
import traceback
from .repo import MDRepository
from .pipes import plumbing
from .constants import config, parse_options


def main():
    """
    The main entrypoint for the pyFF cmdline tool.
    """
    args = parse_options("pyff", __doc__, 'hm:', ['help', 'loglevel=', 'logfile=', 'version', 'module='])

    log_args = {'level': config.loglevel}
    if config.logfile is not None:
        log_args['filename'] = config.logfile
    logging.basicConfig(**log_args)

    config.modules.append('pyff.builtins')
    for mn in config.modules:
        importlib.import_module(mn)
    config.update_frequency = 0
    try:
        md = MDRepository()
        for p in args:
            plumbing(p).process(md, state={'batch': True, 'stats': {}})
        sys.exit(0)
    except Exception as ex:
        logging.debug(traceback.format_exc())
        logging.error(ex)
        sys.exit(-1)


if __name__ == "__main__":  # pragma: no cover
    main()
