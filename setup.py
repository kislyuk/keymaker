#!/usr/bin/env python

import os, glob
from setuptools import setup, find_packages

install_requires = [line.rstrip() for line in open(os.path.join(os.path.dirname(__file__), "requirements.txt"))]
tests_require = ["coverage", "flake8", "wheel"]

setup(
    name='keymaker',
    version='1.0.5',
    url='https://github.com/kislyuk/keymaker',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description='Lightweight SSH key management on AWS EC2',
    long_description=open('README.rst').read(),
    install_requires=install_requires,
    tests_require=tests_require,
    packages=find_packages(exclude=['test']),
    scripts=glob.glob('scripts/*'),
    platforms=['MacOS X', 'Posix'],
    include_package_data=True,
    test_suite='test',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
