#!/usr/bin/env python3

# Depends on:
# -pycrypto

from Crypto.Hash import SHA
from base64 import b32encode, b64encode
from collections import namedtuple
from getpass import getpass
import sys


def shrink(s, n=None):
    """
    Shrink `s` in to byte width `n`. If `n` is not given, it is half the width
    of `s` rounded up to next integer number.
    """
    if not isinstance(s, (bytes, bytearray)):
        s = memoryview(s).tobytes()
    if n is None:
        n = len(s) // 2 + len(s) % 2
    x = bytearray(n)
    for i, b in enumerate(s):
        x[i % n] ^= b
    return bytes(x)

def calc_key(servname, username, key):
    h = SHA.new()
    for s in (servname, username, key):
        h.update(s.encode('UTF-8'))
    return h.digest()

def as_readable(key, do_group=False):
    k = b32encode(shrink(key, 10)).decode('ascii')
    if do_group:
        return '-'.join([k[i:i+4] for i in range(0, len(k), 4)])
    else:
        return k

def as_old_style(key):
    return b64encode(key).decode('ascii')

def get_input(prompt, hide=False):
    print(prompt)
    if hide:
        answer = getpass('> ')
    else:
        answer = input('> ')
    if answer == '':
        sys.exit(1)
    else:
        return answer

def get_skeleton_key():
    """Requests user for the skeleton key and returns the SHA256 of the key once
    it is inputted successfully.
    """
    while True:
        skeleton_key = get_input('Please enter the skeleton key:', True)
        confirm_key = get_input('Please re-enter the skeleton key to confirm:',
                                True)
        if skeleton_key != confirm_key:
            print('The skeleton key and its confirmation didn\'t match. '
                  'Please re-enter.')
        else:
            return skeleton_key

def ui():
    skeleton_key = get_skeleton_key()
    servname = get_input('Please enter the service name:')
    username = get_input('Please enter the user name:')
    return (servname, username, skeleton_key)

if __name__ == '__main__':
    key = calc_key(*ui())
    print(as_readable(key, True))
    print(as_old_style(key))
