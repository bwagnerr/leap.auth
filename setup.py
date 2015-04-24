#!/usr/bin/env python

from setuptools import setup

import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='leap-srp',
      version='0.1',
      description='Library to authenticate with a leap platform instance',
      long_description=read('README.md'),
      author='Thoughtworks',
      author_email='pixelated-team@thoughtworks.com',
      url='http://leap.se',
      packages=[
          'leap'
      ],
      install_requires=[
          'srp',
          'requests'
      ],
      test_suite='nose.collector',
      tests_require=['nose'])
