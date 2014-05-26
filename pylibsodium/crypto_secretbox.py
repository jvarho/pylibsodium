#!/usr/bin/env python

# Copyright (c) 2014, Jan Varho
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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

