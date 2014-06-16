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

"""Extension for easily creating session key-pairs for forward secrecy"""

from .crypto_box import *


def crypto_box_session_keypair(pk, sk):
    """Generates session keypair for sk with the public key boxed for pk"""
    spk, ssk = crypto_box_keypair()
    return crypto_box(spk, pk, sk), ssk


def crypto_box_session_keypair_open(spk, pk, sk):
    """Opens a public session key encrypted by pk for sk"""
    return crypto_box_open(spk, pk, sk)


if __name__ == "__main__":
    pk1, sk1 = crypto_box_keypair()
    pk2, sk2 = crypto_box_keypair()

    # Both generate session keypairs sending the pks over
    spk1, ssk1 = crypto_box_session_keypair(pk2, sk1)
    spk2, ssk2 = crypto_box_session_keypair(pk1, sk2)

    # Both open the public keys using their long term keys
    spk2 = crypto_box_session_keypair_open(spk2, pk2, sk1)
    spk1 = crypto_box_session_keypair_open(spk1, pk1, sk2)

    # Now they can use the session keys normally
    cipher = crypto_box(b'Hello World!', spk2, ssk1)
    print(cipher)
    msg = crypto_box_open(cipher, spk1, ssk2)
    print(msg)

