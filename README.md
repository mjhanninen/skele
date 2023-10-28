Skele
=====

> 🖐 **Warning:** Do not use this.  Just don't.  Way better and actually secure
> alternatives exist.

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

```
$ skele
Skele, version 0.2.0
Skeleton key?
> <your skeleton key, e.g. "foo bar baz">
Please re-enter the skeleton key to confirm
> <e.g. "foo bar baz" again>
Confirmed: The fingerprint of the skeleton key is 9Ygh1tcz
Domain?
> example.com
Identity?
> john
1: Xr7w-Mmgv-Bzdz-Wr7q
2: 873S-Sj3y-653A-X6z1
3: 4Wzy-Kks2-Z98y-S5sn
4: Ajkc-6Cyk-Txnb-Mrtw
5: Dxmw-1Xmy-As0t-V2dc
Domain?
> ^D
```

[diceware]: http://world.std.com/~reinhold/diceware.html
    (The Diceware Passphrase Home Page)


Installation
------------

If you just want to use the package:

```
$ cd path/to/repository
$ cd skele
$ cargo install
$ skele
```


License
-------

Copyright (C) 2014-2016 Matti Hänninen

This software is licensed under the BSD 3-Clause License. Please see
`LICENSE.txt` for details.
