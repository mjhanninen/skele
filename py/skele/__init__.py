#!/usr/bin/env python3

from Crypto.Hash import SHA256
from getpass import getpass
import sys

def calc_key(servname, username, skeleton_key, count=1):
    sha = SHA256.new()
    sha.update(skeleton_key)
    sha.update(servname.encode('UTF-8'))
    sha.update(username.encode('UTF-8'))
    keys = []
    for i in range(count):
        digest = sha.digest()
        # Truncate to the first 80 bits; would prefer to use SHA-512/80 but
        # PyCrypto supports neither SHA-512/t directly nor setting the initial
        # hash value.
        keys.append(digest[:10])
        sha.update(skeleton_key)
        sha.update(digest)
    return keys

def _b32(b):
    assert(len(b) % 5 == 0)
    b = memoryview(b)
    e = memoryview(bytearray(8 * (len(b) // 5)))
    for i in range(0, len(b) // 5):
        q = b[5 * i : 5 * (i + 1)]
        r = e[8 * i : 8 * (i + 1)]
        r[0] =  (q[0] >> 3)
        r[1] = ((q[0] & 0b00000111) << 2) + (q[1] >> 6)
        r[2] =  (q[1] & 0b00111110) >> 1
        r[3] = ((q[1] & 0b00000001) << 4) + (q[2] >> 4)
        r[4] = ((q[2] & 0b00001111) << 1) + (q[3] >> 7)
        r[5] =  (q[3] & 0b01111100) >> 2
        r[6] = ((q[3] & 0b00000011) << 3) + (q[4] >> 5)
        r[7] =  (q[4] & 0b00011111)
    return e.tobytes()

CROCKFORD_BASE = \
    '0123456789abcdefghjkmnpqrstvwxyz'.encode('ascii') + bytes(256 - 32)

def b32crockford(b):
    """Encodes the given bytes with Crockford's B32 encoding. Returns bytes.
    """
    return _b32(b).translate(CROCKFORD_BASE)

def capfirst(s):
    """Capitalizes the first alphabet of the string.
    """
    for i, c in enumerate(s):
        if c.isalpha():
            return s[:i] + s[i:i+1].upper() + s[i+1:]
    else:
        return s

def as_readable(key):
    """Converts `key` into human readable and usable form.
    """
    b32 = b32crockford(key).decode('ascii')
    groups = [capfirst(b32[i:i+4]) for i in range(0, len(b32), 4)]
    return '-'.join(groups)

def get_input(prompt, hide=False):
    print(prompt)
    try:
        if hide:
            answer = getpass('> ')
        else:
            answer = input('> ')
    except EOFError:
        print('')
        sys.exit(1)
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
            hash = SHA256.new()
            hash.update(skeleton_key.encode('UTF-8'))
            return hash.digest()

def main():
    skeleton_key = get_skeleton_key()
    while True:
        servname = get_input('Please enter the service name:')
        username = get_input('Please enter the user name:')
        for i, key in enumerate(calc_key(servname, username, skeleton_key, 5)):
            print('{:d}. {:s}'.format(i + 1, as_readable(key)))

if __name__ == '__main__':
    main()
