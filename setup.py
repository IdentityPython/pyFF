#!/usr/bin/env python
from distutils.core import setup
from setuptools import find_packages
import sys, os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
NEWS = open(os.path.join(here, 'NEWS.txt')).read()

version = '0.10.0dev'

install_requires = [
    'lxml >=3.0',
    'pyyaml >=3.10',
    'pyXMLSecurity >=0.8',
    'cherrypy >=3.2.0',
    'iso8601 >=0.1.4',
    'simplejson >=2.6.2',
    'jinja2',
    'httplib2 >=0.7.7',
    'ipaddr',
    'publicsuffix',
    'redis',
    'futures',
    'requests'
]

setup(name='pyFF',
      version=version,
      description="Federation Feeder",
      long_description=README + '\n\n' + NEWS,
      classifiers=[
          # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      ],
      keywords='identity federation saml metadata',
      author='Leif Johansson',
      author_email='leifj@sunet.se',
      url='http://blogs.mnt.se',
      license='BSD',
      setup_requires=['nose>=1.0'],
      tests_require=['nose>=1.0', 'mock', 'mako', 'mockredispy', 'testfixtures'],
      test_suite="nose.collector",
      packages=find_packages('src'),
      package_dir={'': 'src'},
      include_package_data=True,
      package_data={
          'pyff': ['xslt/*.xsl',
                   'site/static/js/*.js',
                   'site/static/js/select2/*',
                   'site/static/css/font-awesome/fonts/*',
                   'site/static/css/font-awesome/css/*',
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
