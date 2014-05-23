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


def crypto_auth(message, key):
    """Authenticates bytes with key, returning an authenticator"""
    if not isinstance(message, bytes):
        raise TypeError('crypto_auth message should be a byte string')
    buf = _buf(len(message) + crypto_auth_BYTES)
    if _lib.crypto_auth(buf, message, len(message), key):
        raise ValueError('crypto_auth failed')
    return buf.raw


def crypto_auth_verify(auth, message, key):
    """Verifies a message, returning True if the authenticator matches"""
    if not isinstance(auth, bytes):
        raise TypeError('crypto_auth authenticator should be a byte string')
    if not isinstance(message, bytes):
        raise TypeError('crypto_auth message should be a byte string')
    return 0 == _lib.crypto_auth_verify(auth, message, len(message), key)


if __name__ == "__main__":
    key = urandom(crypto_auth_KEYBYTES)
    msg = b'Hello World!'
    auth = crypto_auth(msg, key)
    print(auth)
    print(crypto_auth_verify(auth, msg, key))

