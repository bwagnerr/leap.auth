#!/usr/bin/env python

from setuptools import setup

import os


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='leap-srp',
      version='0.1.2',
      description='Library to authenticate with a LEAP platform',
      long_description=read('README.rst'),
      author='Pixelated Project',
      author_email='team@pixelated-project.org',
      url='http://github.com/pixelated-project/leap_srp',
      packages=[
          'leap'
      ],
      install_requires=[
          'srp',
          'requests'
      ],
      test_suite='nose.collector',
      tests_require=['nose'],
      include_package_data=True)
