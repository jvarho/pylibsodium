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

"""Bindings for crypto_sign public key signatures"""

from ctypes import create_string_buffer as _buf
from ctypes import c_char_p, c_ulonglong, c_void_p, pointer

from .libsodium import _lib

try:
    crypto_sign_BYTES           = _lib.crypto_sign_bytes()
    crypto_sign_SEEDBYTES       = _lib.crypto_sign_seedbytes()
    crypto_sign_PUBLICKEYBYTES  = _lib.crypto_sign_publickeybytes()
    crypto_sign_SECRETKEYBYTES  = _lib.crypto_sign_secretkeybytes()

    _lib.crypto_sign_primitive.restype = c_char_p
    crypto_sign_PRIMITIVE       = _lib.crypto_sign_primitive()

    _lib.crypto_sign_keypair.argtypes = [
        c_void_p,   # pk
        c_void_p,   # sk
    ]

    _lib.crypto_sign.argtypes = [
        c_void_p,       # out
        c_void_p,       # outlen
        c_void_p,       # msg
        c_ulonglong,    # msglen
        c_void_p,       # sk
    ]

    _lib.crypto_sign_open.argtypes = [
        c_void_p,       # out
        c_void_p,       # outlen
        c_void_p,       # sign
        c_ulonglong,    # signlen
        c_void_p,       # pk
    ]
except AttributeError as e:
    raise ImportError('Incompatible libsodium: %s (%s)' % (_lib._name, str(e)))


def crypto_sign_keypair():
    """Returns a randomly generated keypair (pk, sk)"""
    pk = _buf(crypto_sign_PUBLICKEYBYTES)
    sk = _buf(crypto_sign_SECRETKEYBYTES)
    _lib.crypto_sign_keypair(pk, sk)
    return pk.raw, sk.raw


def crypto_sign(message, sk):
    """Signs bytes with sk, returning the signed message"""
    if not isinstance(message, bytes):
        raise TypeError('crypto_sign message should be a byte string')
    buf = _buf(len(message) + crypto_sign_BYTES)
    slen = pointer(c_ulonglong(-1))
    if _lib.crypto_sign(buf, slen, message, len(message), sk):
        raise ValueError('crypto_sign failed')
    return buf.raw[:slen.contents.value]


def crypto_sign_open(signed, pk):
    """Decrypts a signed message from pk, returning the plaintext message"""
    if not isinstance(signed, bytes):
        raise TypeError('crypto_sign message should be a byte string')
    buf = _buf(len(signed))
    mlen = pointer(c_ulonglong(-1))
    if _lib.crypto_sign_open(buf, mlen, signed, len(signed), pk):
        raise ValueError('crypto_sign_open failed')
    return buf.raw[:mlen.contents.value]


if __name__ == "__main__":
    pk, sk = crypto_sign_keypair()
    signed = crypto_sign(b'Hello World!', sk)
    print(signed)
    msg = crypto_sign_open(signed, pk)
    print(msg)

