#!/usr/bin/env python

# Copyright (c) 2014 Jan Varho
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Bindings for crypto_secretbox secret key encryption"""

from ctypes import create_string_buffer as _buf
from ctypes import c_char_p, c_ulonglong, c_void_p
from os import urandom

from .libsodium import _lib

try:
    crypto_secretbox_KEYBYTES         = _lib.crypto_secretbox_keybytes()
    crypto_secretbox_NONCEBYTES       = _lib.crypto_secretbox_noncebytes()
    crypto_secretbox_MACBYTES         = _lib.crypto_secretbox_macbytes()

    _lib.crypto_secretbox_primitive.restype = c_char_p
    crypto_secretbox_PRIMITIVE        = _lib.crypto_secretbox_primitive()

    _lib.crypto_secretbox_easy.argtypes = [
        c_void_p,       # out
        c_void_p,       # msg
        c_ulonglong,    # msglen
        c_void_p,       # nonce
        c_void_p,       # key
    ]

    _lib.crypto_secretbox_open_easy.argtypes = [
        c_void_p,       # out
        c_void_p,       # ct
        c_ulonglong,    # ctlen
        c_void_p,       # nonce
        c_void_p,       # key
    ]
except AttributeError as e:
    raise ImportError('Incompatible libsodium: %s (%s)' % (_lib._name, str(e)))


if crypto_secretbox_NONCEBYTES < 16:
    raise ImportError(
        'Incompatible libsodium: %s (crypto_secretbox_NONCEBYTES too low)' %
        _lib._name
    )


def crypto_secretbox(message, key):
    """Encrypts bytes with secret key, returning the ciphertext"""
    if not isinstance(message, bytes):
        raise TypeError('crypto_secretbox message should be a byte string')
    nonce = urandom(crypto_secretbox_NONCEBYTES)
    buf = _buf(len(message) + crypto_secretbox_MACBYTES)
    if _lib.crypto_secretbox_easy(buf, message, len(message), nonce, key):
        raise ValueError('crypto_secretbox failed')
    return buf.raw + nonce


def crypto_secretbox_open(ciphertext, key):
    """Decrypts a secret key encrypted message, returning the plaintext"""
    if not isinstance(ciphertext, bytes):
        raise TypeError('crypto_secretbox ciphertext should be a byte string')
    clen = len(ciphertext) - crypto_secretbox_NONCEBYTES
    nonce = ciphertext[-crypto_secretbox_NONCEBYTES:]
    buf = _buf(clen - crypto_secretbox_MACBYTES)
    if _lib.crypto_secretbox_open_easy(buf, ciphertext, clen, nonce, key):
        raise ValueError('crypto_secretbox_open failed')
    return buf.raw


if __name__ == "__main__":
    key = urandom(crypto_secretbox_KEYBYTES)
    cipher = crypto_secretbox(b'Hello World!', key)
    print(cipher)
    msg = crypto_secretbox_open(cipher, key)
    print(msg)

