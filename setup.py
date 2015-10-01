# -*- coding: utf-8 -*-

"""
Skele
=====

**Skele** is a command line utility for computing unique passwords for
different services and identities.

Skele is based on the idea that you can use a cryptographic password in
combination with your identity to calculate a password that you can use with
your identity to form your credentials.


Usage
-----

Assuming you have generated yourself a [cryptographic passphrase][diceware]
(like `foo bar baz` below) you can generate yourself unique passwords tied to
your online identity as follows:

    $ skele
    Please enter the skeleton key:
    > <foo bar baz>
    Please re-enter the skeleton key to confirm:
    > <foo bar baz>
    Please enter the service name:
    > example.com
    Please enter the user name:
    > john
    1. Xr7w-Mmgv-Bzdz-Wr7q
    2. 873S-Sj3y-653A-X6z1
    3. 4Wzy-Kks2-Z98y-S5sn
    4. Ajkc-6Cyk-Txnb-Mrtw
    5. Dxmw-1Xmy-As0t-V2dc
    Please enter the service name:
    > ^D

[diceware]: http://world.std.com/~reinhold/diceware.html
    (The Diceware Passphrase Home Page)
"""

from setuptools import setup

setup(
    name = 'Skele',
    version = '0.1.0',
    url = 'http://github.com/mjhanninen/skele.py',
    license = 'BSD',
    author = 'Matti Hänninen',
    author_email = 'matti@mjhanninen.com',
    description = 'A tool for computing unique passwords for your online '
                  'identities',
    long_description = __doc__,
    package_dir = {'': 'py'},
    packages = ['skele'],
    zip_safe = True,
    platforms = 'any',
    install_requires = ['pycrypto'],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: End Users/Desktop',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security',
    ],
    entry_points = '''
    [console_scripts]
    skele=skele:main
    ''')
