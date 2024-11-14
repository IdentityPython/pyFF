#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from setuptools import setup
from pathlib import PurePath
from platform import python_implementation
from typing import List

from setuptools import find_packages

__author__ = 'Leif Johansson'
__version__ = '2.1.3'


def load_requirements(path: PurePath) -> List[str]:
    """ Load dependencies from a requirements.txt style file, ignoring comments etc. """
    res = []
    with open(path) as fd:
        for line in fd.readlines():
            while line.endswith('\n') or line.endswith('\\'):
                line = line[:-1]
            line = line.strip()
            if not line or line.startswith('-') or line.startswith('#'):
                continue
            res += [line]
    return res


here = PurePath(__file__)
README = open(here.with_name('README.rst')).read()
NEWS = open(here.with_name('NEWS.txt')).read()

install_requires = load_requirements(here.with_name('requirements.txt'))
tests_require = load_requirements(here.with_name('test_requirements.txt'))

python_implementation_str = python_implementation()

setup(
    name='pyFF',
    version=__version__,
    description="Federation Feeder",
    long_description=README + '\n\n' + NEWS,
    classifiers=[
        # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='identity federation saml metadata',
    author=__author__,
    author_email='leifj@sunet.se',
    url='https://pyff.io',
    license='BSD',
    tests_require=tests_require,
    packages=find_packages('src'),
    package_dir={'': 'src'},
    include_package_data=True,
    package_data={'pyff': ['xslt/*.xsl', 'schema/*.xsd']},
    zip_safe=False,
    install_requires=install_requires,
    scripts=['scripts/mirror-mdq.sh'],
    entry_points={
        'console_scripts': ['pyff=pyff.md:main', 'pyffd=pyff.mdq:main', 'samldiff=pyff.tools:difftool'],
        'paste.app_factory': ['pyffapp=pyff.wsgi:app_factory'],
        'paste.server_runner': ['pyffs=pyff.wsgi:server_runner'],
    },
    message_extractors={'src': [('**.py', 'python', None), ('**/templates/**.html', 'mako', None),]},
    python_requires='>=3.7',
)
