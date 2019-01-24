#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from distutils.core import setup
from platform import python_implementation
from sys import version_info

from os.path import abspath, dirname, join
from setuptools import find_packages

__author__ = 'Leif Johansson'
__version__ = '0.10.0.dev0'

here = abspath(dirname(__file__))
README = open(join(here, 'README.rst')).read()
NEWS = open(join(here, 'NEWS.txt')).read()

install_requires = [
    'mako',
    'six',
    'urllib3',
    'idna',
    'lxml >=4.1.1',
    'pyyaml >=3.10',
    'pyXMLSecurity >=0.15',
    'cherrypy',
    'iso8601 >=0.1.4',
    'simplejson >=2.6.2',
    'jinja2',
    'httplib2 >=0.7.7',
    'six>=1.11.0',
    'ipaddr',
    'publicsuffix',
    'redis',
    'futures',
    'requests',
    'requests_cache',
    'requests_file',
    'pyconfig',
    'pyyaml',
    'multiprocess',
    'minify',
    'whoosh'
]

python_implementation_str = python_implementation()

setup(name='pyFF',
      version=__version__,
      description="Federation Feeder",
      long_description=README + '\n\n' + NEWS,
      classifiers=[
          # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      ],
      keywords='identity federation saml metadata',
      author=__author__,
      author_email='leifj@sunet.se',
      url='http://blogs.mnt.se',
      license='BSD',
      setup_requires=['nose>=1.0'],
      tests_require=['pbr', 'coverage', 'nose>=1.0', 'mock', 'mako', 'mockredispy', 'testfixtures'],
      test_suite="nose.collector",
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      package_data={
          'pyff': ['xslt/*.xsl',
                   'site/static/js/*.js',
                   'site/static/js/select2/*',
                   'site/static/fonts/*',
                   'site/static/css/*.css',
                   'site/templates/*',
                   'site/icons/*',
                   'site/static/bootstrap/fonts/*',
                   'site/static/bootstrap/js/*',
                   'site/static/bootstrap/css/*',
                   'site/static/bootstrap/img/*',
                   'schema/*.xsd']
      },
      zip_safe=False,
      install_requires=install_requires,
      entry_points={
          'console_scripts': ['pyff=pyff.md:main', 'pyffd=pyff.mdx:main']
      },
      message_extractors={'src': [
          ('**.py', 'python', None),
          ('**/templates/**.html', 'mako', None),
      ]},
)
