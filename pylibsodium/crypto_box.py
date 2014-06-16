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

"""Bindings for crypto_box public key encryption"""

from ctypes import create_string_buffer as _buf
from ctypes import c_char_p, c_ulonglong, c_void_p
from os import urandom

from .libsodium import _lib

try:
    crypto_box_PUBLICKEYBYTES   = _lib.crypto_box_publickeybytes()
    crypto_box_SECRETKEYBYTES   = _lib.crypto_box_secretkeybytes()
    crypto_box_NONCEBYTES       = _lib.crypto_box_noncebytes()
    crypto_box_MACBYTES         = _lib.crypto_box_macbytes()

    _lib.crypto_box_primitive.restype = c_char_p
    crypto_box_PRIMITIVE        = _lib.crypto_box_primitive()

    _lib.crypto_box_keypair.argtypes = [
        c_void_p,   # pk
        c_void_p,   # sk
    ]

    _lib.crypto_box_easy.argtypes = [
        c_void_p,       # out
        c_void_p,       # msg
        c_ulonglong,    # msglen
        c_void_p,       # nonce
        c_void_p,       # pk
        c_void_p,       # sk
    ]

    _lib.crypto_box_open_easy.argtypes = [
        c_void_p,       # out
        c_void_p,       # ct
        c_ulonglong,    # ctlen
        c_void_p,       # nonce
        c_void_p,       # pk
        c_void_p,       # sk
    ]
except AttributeError as e:
    raise ImportError('Incompatible libsodium: %s (%s)' % (_lib._name, str(e)))


if crypto_box_NONCEBYTES < 16:
    raise ImportError(
        'Incompatible libsodium: %s (crypto_box_NONCEBYTES too low)' %
        _lib._name
    )


def crypto_box_keypair():
    """Returns a randomly generated keypair (pk, sk)"""
    pk = _buf(crypto_box_PUBLICKEYBYTES)
    sk = _buf(crypto_box_SECRETKEYBYTES)
    _lib.crypto_box_keypair(pk, sk)
    return pk.raw, sk.raw


def crypto_box(message, pk, sk):
    """Encrypts bytes to pk, returning the boxed ciphertext"""
    if not isinstance(message, bytes):
        raise TypeError('crypto_box message should be a byte string')
    nonce = urandom(crypto_box_NONCEBYTES)
    buf = _buf(len(message) + crypto_box_MACBYTES)
    if _lib.crypto_box_easy(buf, message, len(message), nonce, pk, sk):
        raise ValueError('crypto_box failed')
    return buf.raw + nonce


def crypto_box_open(ciphertext, pk, sk):
    """Decrypts a boxed message from pk, returning the plaintext message"""
    if not isinstance(ciphertext, bytes):
        raise TypeError('crypto_box ciphertext should be a byte string')
    clen = len(ciphertext) - crypto_box_NONCEBYTES
    nonce = ciphertext[-crypto_box_NONCEBYTES:]
    buf = _buf(clen - crypto_box_MACBYTES)
    if _lib.crypto_box_open_easy(buf, ciphertext, clen, nonce, pk, sk):
        raise ValueError('crypto_box_open failed')
    return buf.raw


__all__ = [
    'crypto_box_keypair',
    'crypto_box',
    'crypto_box_open',
]


if __name__ == "__main__":
    pk, sk = crypto_box_keypair()
    pk2, sk2 = crypto_box_keypair()
    assert pk != pk2 and sk != sk2
    cipher = crypto_box(b'Hello World!', pk2, sk)
    print(cipher)
    msg = crypto_box_open(cipher, pk, sk2)
    print(msg)

