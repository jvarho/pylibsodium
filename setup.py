#!/usr/bin/env python

from distutils.core import setup

# Read README for long description
readme = open('README').read()
try:
    import pypandoc
    pypandoc.get_pandoc_formats()
    readme = pypandoc.convert(readme, to='rst', format='markdown')
except:
    pass

with open('pylibsodium/__init__.py') as f:
    for l in f.readlines():
        if l.startswith('__version__'):
            version = l.split('=')[1].strip().strip("'")

setup(name='pylibsodium',
    version=version,
    description='Python bindings to system libsodium',
    long_description=readme,
    author='Jan Varho',
    author_email='jan@varho.org',
    url='https://github.com/jvarho/pylibsodium',
    license='ISC License',
    packages=['pylibsodium'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
    ],
)

