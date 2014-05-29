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
    """Signs bytes with sk, returning a signed message"""
    if not isinstance(message, bytes):
        raise TypeError('crypto_sign message should be a byte string')
    buf = _buf(len(message) + crypto_sign_BYTES)
    slen = pointer(c_ulonglong(-1))
    if _lib.crypto_sign(buf, slen, message, len(message), sk):
        raise ValueError('crypto_sign failed')
    return buf.raw[:slen.contents.value]


def crypto_sign_open(signed, pk):
    """Verifies a signed message from pk, returning the enclosed message"""
    if not isinstance(signed, bytes):
        raise TypeError('crypto_sign message should be a byte string')
    buf = _buf(len(signed))
    mlen = pointer(c_ulonglong(-1))
    if _lib.crypto_sign_open(buf, mlen, signed, len(signed), pk):
        raise ValueError('crypto_sign_open failed')
    return buf.raw[:mlen.contents.value]


def _sig_is_before():
    """Finds where crypto_sign puts the signature so it can be detached"""
    pk, sk = crypto_sign_keypair()
    msg = b'.' + b'X'*crypto_sign_BYTES + b'.'
    signed = crypto_sign(msg, sk)
    if signed.endswith(msg):
        return True
    if signed.startswith(msg):
        return False
    raise ImportError(
        'Incompatible libsodium: %s (signature not found)' % _lib._name
    )
_sig_before = _sig_is_before()


def crypto_signature(message, sk):
    """Signs bytes with sk, returning the signature"""
    signed = crypto_sign(message, sk)
    if _sig_before:
        return signed[:crypto_sign_BYTES]
    return signed[-crypto_sign_BYTES:]


def crypto_signature_verify(signature, message, pk):
    """Verifies a message, returning True if the signature matches pk"""
    if not isinstance(signature, bytes):
        raise TypeError('crypto_signature_verify signature should be bytes')
    if not isinstance(signature, bytes):
        raise TypeError('crypto_signature_verify message should be bytes')
    signed = signature + message if _sig_before else message + signature
    try:
        return crypto_sign_open(signed, pk) == message
    except ValueError:
        return False


__all__ = [
    'crypto_sign_keypair', 'crypto_sign', 'crypto_sign_open',
    'crypto_signature', 'crypto_signature_verify'
]


if __name__ == "__main__":
    pk, sk = crypto_sign_keypair()
    pk2, sk2 = crypto_sign_keypair()
    assert pk != pk2 and sk != sk2
    signed = crypto_sign(b'Hello World!', sk)
    print(signed)
    msg = crypto_sign_open(signed, pk)
    print(msg)
    s = crypto_signature(msg, sk)
    print(crypto_signature_verify(s, msg, pk))
    print(crypto_signature_verify(s, msg, sk))

