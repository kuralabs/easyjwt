# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 KuraLabs S.R.L
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Test jwtpie module.
"""

from time import sleep

from pytest import raises

from jwtpie import JWTPie, JWTExpired, JWTInvalid


def test_jwtpie():

    session = {
        'user': 'jane_doe@anonymous.io',
        'name': 'Jane Doe',
    }
    size = 256

    # Test key generation
    signkey = JWTPie.generate(size)
    encryptkey = JWTPie.generate(size)

    # Test encryption / decryption
    mgr = JWTPie(
        issuer='jwtpietest',
        signkey=signkey,
        encryptkey=encryptkey,
        expiration_s=10,
        leeway_s=1,
    )

    token = mgr.encrypt(session)
    assert JWTPie.validate(token)

    decoded = mgr.decrypt(token)
    assert decoded == session

    # Test invalid
    with raises(ValueError):
        JWTPie.validate('asdasdasdasdaasd')

    mgr2 = JWTPie()

    with raises(JWTInvalid):
        mgr2.decrypt(token)

    # Test compression
    mgr3 = JWTPie(
        signkey=signkey,
        encryptkey=encryptkey,
        compress=False,
    )
    mgr4 = JWTPie(
        signkey=signkey,
        encryptkey=encryptkey,
        compress=True,
    )

    payload = ''.join(str(num) for num in range(10, 99))

    large_session = {}
    for cycle in range(10):
        thing = '{}-{}'.format(cycle, payload)
        large_session[thing] = thing

    uncompressed_token = mgr3.encrypt(large_session)
    compressed_token = mgr4.encrypt(large_session)

    assert len(compressed_token) < len(uncompressed_token)
    assert mgr3.decrypt(uncompressed_token) == mgr4.decrypt(compressed_token)

    # Test expiration
    with raises(JWTExpired):
        token = mgr.encrypt(session, expires_in_s=1)
        sleep(5)
        mgr.decrypt(token)
