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

"""Bindings for crypto_auth secret key authentication"""

from ctypes import create_string_buffer as _buf
from ctypes import c_char_p, c_ulonglong, c_void_p, pointer
from os import urandom

from .libsodium import _lib

try:
    crypto_auth_BYTES           = _lib.crypto_auth_bytes()
    crypto_auth_KEYBYTES        = _lib.crypto_auth_keybytes()

    _lib.crypto_auth_primitive.restype = c_char_p
    crypto_auth_PRIMITIVE       = _lib.crypto_auth_primitive()

    _lib.crypto_auth.argtypes = [
        c_void_p,       # out
        c_void_p,       # msg
        c_ulonglong,    # msglen
        c_void_p,       # key
    ]

    _lib.crypto_auth_verify.argtypes = [
        c_void_p,       # auth
        c_void_p,       # msg
        c_ulonglong,    # msglen
        c_void_p,       # key
    ]
except AttributeError as e:
    raise ImportError('Incompatible libsodium: %s (%s)' % (_lib._name, str(e)))


def crypto_auth_key():
    """Generates a random crypto_auth secret key"""
    return urandom(crypto_auth_KEYBYTES)


def crypto_auth(message, key):
    """Authenticates bytes with key, returning an authenticator"""
    if not isinstance(message, bytes):
        raise TypeError('crypto_auth message should be a byte string')
    buf = _buf(crypto_auth_BYTES)
    if _lib.crypto_auth(buf, message, len(message), key):
        raise ValueError('crypto_auth failed')
    return buf.raw


def crypto_auth_verify(auth, message, key):
    """Verifies a message, returning True if the authenticator matches key"""
    if not isinstance(auth, bytes):
        raise TypeError('crypto_auth authenticator should be a byte string')
    if not isinstance(message, bytes):
        raise TypeError('crypto_auth message should be a byte string')
    return 0 == _lib.crypto_auth_verify(auth, message, len(message), key)


def crypto_authenticated(message, key):
    """Authenticates bytes with key, returning an authenticated message"""
    return crypto_auth(message, key) + message


def crypto_authenticated_open(authenticated, key):
    """Verifies an authenticated message, the enclosed message"""
    auth = authenticated[:crypto_auth_BYTES]
    message = authenticated[crypto_auth_BYTES:]
    if not crypto_auth_verify(auth, message, key):
        print(auth, message)
        raise ValueError('crypto_authenticated_open failed')
    return message


__all__ = [
    'crypto_auth_key', 'crypto_auth', 'crypto_auth_verify',
    'crypto_authenticated', 'crypto_authenticated_open'
]


if __name__ == "__main__":
    key = crypto_auth_key()
    authenticated = crypto_authenticated(b'Hello World!', key)
    print(authenticated)
    msg = crypto_authenticated_open(authenticated, key)
    print(msg)
    auth = crypto_auth(msg, key)
    print(auth)
    print(crypto_auth_verify(auth, msg, key))
    print(crypto_auth_verify(auth, msg, urandom(crypto_auth_KEYBYTES)))

