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


Installation
------------

If you want to just use the package:

    $ cd path/to/project
    $ python3 setup.py install
    $ skele

In case you want hack around with the sources you probably want to set up a
project local virtual environment:

    $ cd path/to/project
    $ ./bin/activate
    $ python3 -m skele

The virtual environment is set up to `./.ve` during the first time. This may
take a moment or two.
