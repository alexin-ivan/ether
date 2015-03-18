
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

##############################################################################
from distutils.core import setup, Extension
##############################################################################
VERSION = '1.0'

EXTRA_COMPILE_ARGS = [
    '-Wall',
    '-fno-strict-aliasing'
]

PcapLibExt = Extension(
    'ether/cether/pcaplib',
    sources=['ether/cether/pcaplib.c'],
    libraries=['crypto', 'pcap']
)

setup_args = dict(
    name='ether',
    version=VERSION,
    description='Description',
    long_description='Long Description',
    license='GNU General Public License v3',
    author='Ivan Alechin',
    author_email='alexin.ivan@gmail.com',
    url='http://vvs.ru',
    classifiers=[
        'Development Status :: 1 - Alpha',
        'Environment :: GUI',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Natural Language :: English, Russian',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Security'
    ],
    platforms=['any'],
    packages=['ether'],
    py_modules=[],
    ext_modules=[PcapLibExt],
    options={'install': {'optimize': 1}},
    install_requires=[
        'graphviz',
        'scapy',
        'networkx',
        'netaddr',
    ],
)

if __name__ == '__main__':
    setup(**setup_args)
