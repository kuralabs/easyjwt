# -*- coding: utf-8 -*-
#
# Copyright (C) 2016-2021 KuraLabs S.R.L
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
Easily encrypt and decrypt JWT tokens.
"""

__author__ = 'KuraLabs S.R.L'
__email__ = 'info@kuralabs.io'
__version__ = '1.0.0'


from time import time
from re import compile
from logging import getLogger
from base64 import b64encode, b64decode
from zlib import compress, decompress, Z_BEST_COMPRESSION

from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT, JWTExpired
from jwcrypto.jwe import InvalidJWEData as JWTInvalid


log = getLogger(__name__)


try:
    # The fastest JSON encoder/decoder coded in Rust
    from orjson import loads, dumps as _dumps
    log.info('Using orjson JSON encoder/decoder')

    def dumps(data):
        return _dumps(data).decode('utf-8')

except ImportError:

    try:
        # Ultrafast JSON encoder/decoder coded in C
        from ujson import loads, dumps as _dumps
        log.info('Using ujson JSON encoder/decoder')

        def dumps(data):
            return _dumps(data, ensure_ascii=False)

    except ImportError:

        # Standard library JSON encoder/decoder coded in Python
        from json import loads, dumps as _dumps
        log.warning(
            'Using Python standard library JSON encoder/decoder, which is '
            'very slow, consider installing orjson or ujson if possible'
        )

        def dumps(data):
            return _dumps(data, separators=(',', ':'))


def ratio(original, compressed):
    """
    Calculate the compression ratio between two strings.

    :param str original: Original data.
    :param str compressed: Compressed data.

    :return: Compression ratio between both.
    :rtype: float
    """
    olen = len(original)
    clen = len(compressed)
    return (olen - clen) / olen


class JWTPie:
    """
    JSON Web Token made easy.

    Standard documentation:

        https://tools.ietf.org/html/rfc7519

    To generate signing and encryption keys run:

    .. code-block:: pycon

       >>> from jwtpie import JWTPie
       >>> size = 256
       >>> JWTPie.generate(size)
       noOIbGe_WLbTfrLIH_grNu0bf5u8Xx-bERELm2TLRaM

    Or launch the interactive wizard::

        python3 -m jwtpie

    And follow the on-screen instructions.

    :param str issuer: Name of the issuer of the tokens.
     Usually the name of the application using this class.
    :param str signkey: Symmetric key for signing.
     See above to generate a key.
    :param str encryptkey: Symmetric key for signing.
     See above to generate a key.
    :param bool compress: Try to compress the user payload data.
    :param int expiration_s: Default number of seconds before a token expires.
    :param int leeway_s: Tolerance (seconds) of time delta.
     Basically if you have several machines decoding tokens, how many seconds
     their clocks can be apart.
    :param str sign_alg: Digital signature or MAC algoritm for JWS.
     See https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1
    :param str enc_alg: Key management algorithm for JWE.
     See https://www.rfc-editor.org/rfc/rfc7518.html#section-4.1
    :param str enc_enc: Content encryption algoritm for JWE:
     See https://www.rfc-editor.org/rfc/rfc7518.html#section-5.1
    """

    """
    Regular expression to match the output of encrypt()

    While we call it a JWT here, it is formally a JWE (JSON Web Encryption)
    wrapping a JWS (JSON Web Signature).

    JWS has the structure:

        b64u(utf8(JOSE Header)) . b64u(Payload) . b64u(Signature)

    While a JWE has the structure:

        b64u(utf8(JOSE Header)) . b64u(Encrypted Key) . b64u(Init Vector) . b64u(Ciphertext) . b64u(Auth Tag)

    * b64u = base64 - url encode
    """  # noqa
    JWT_REGEX = compile(
        r'^'
        r'(?P<jose_header>[a-zA-Z0-9\-_]+)\.'
        r'(?P<encrypted_key>[a-zA-Z0-9\-_]+)\.'
        r'(?P<init_vector>[a-zA-Z0-9\-_]+)\.'
        r'(?P<ciphertext>[a-zA-Z0-9\-_]+)\.'
        r'(?P<auth_tag>[a-zA-Z0-9\-_]+)'
        r'$'
    )

    def __init__(
        self,
        issuer='jwtpie',
        signkey=None,
        encryptkey=None,
        compress=True,
        expiration_s=(60 * 60 * 24 * 14),  # Two weeks
        leeway_s=60,
        sign_alg='HS256',
        enc_alg='A256KW',
        enc_enc='A256CBC-HS512',
    ):
        assert issuer

        if signkey is None:
            log.warning('Missing JWT signing key. Generating one ...')
            signkey = JWK.generate(kty='oct', size=256)
        elif isinstance(signkey, str):
            signkey = JWK(k=signkey, kty='oct')

        assert isinstance(signkey, JWK)

        if encryptkey is None:
            log.warning('Missing JWT encryption key. Generating one ...')
            encryptkey = JWK.generate(kty='oct', size=256)
        elif isinstance(encryptkey, str):
            encryptkey = JWK(k=encryptkey, kty='oct')

        assert isinstance(encryptkey, JWK)

        self.issuer = issuer
        self.signkey = signkey
        self.encryptkey = encryptkey
        self.compress = compress
        self.expiration_s = expiration_s
        self.leeway_s = leeway_s
        self.sign_alg = sign_alg
        self.enc_alg = enc_alg
        self.enc_enc = enc_enc

    def encrypt(self, data, expires_in_s=None):
        """
        Create an encrypted, signed and possible compressed JSON Web Token
        (JWT).

        :param dict data: Arbitrary data to encrypt and sign in a JWT.
        :param int expires_in_s: Number of seconds the token will remain valid.
         If None is given, the default setup in the class constructor will be
         used.

        :return: Encrypted and signed, and possible compressed JWT.
        :rtype: str
        """
        assert isinstance(data, dict)

        now = time()
        dataserial = dumps(data)

        if expires_in_s is None:
            expires_in_s = self.expiration_s

        # Compress token
        cps = False
        if self.compress:
            uncompressed = dataserial.encode(encoding='utf-8')
            compressed = compress(uncompressed, Z_BEST_COMPRESSION)

            compresseddataserial = \
                b64encode(compressed).decode(encoding='ascii')

            cprratio = ratio(dataserial, compresseddataserial)
            # Uncomment for debug. Do not leave commented on production as this
            # may leak user information in logs.
            #
            # print(
            #     'Compression ratio of {:.2f}\n{}\n{}\n{}'.format(
            #         cprratio, dataserial, '-' * 80, compresseddataserial,
            #     )
            # )
            if cprratio > 0.0:
                dataserial = compresseddataserial
                cps = True

        # Build signed token
        signed = JWT(
            header={'alg': self.sign_alg},
            claims={
                # Custom claims
                'cps': cps,
                'dta': dataserial,
                # Standard claims
                # https://tools.ietf.org/html/rfc7519#section-4.1
                'iss': self.issuer,         # issuer name
                'iat': now,                 # issued at
                'nbf': now,                 # not before
                'exp': now + expires_in_s,  # expires at
            },
        )
        signed.make_signed_token(self.signkey)
        signedserial = signed.serialize()

        # Build encrypted token
        encrypted = JWT(
            header={'alg': self.enc_alg, 'enc': self.enc_enc},
            claims={
                # Custom claims
                'dta': signedserial,
                # Standard claims
                # https://tools.ietf.org/html/rfc7519#section-4.1
                'iss': self.issuer,         # issuer name
                'iat': now,                 # issued at
                'nbf': now,                 # not before
                'exp': now + expires_in_s,  # expires at
            },
        )
        encrypted.make_encrypted_token(self.encryptkey)
        encryptedserial = encrypted.serialize()

        return encryptedserial

    def decrypt(self, encryptedserial):
        """
        Decrypt and verify signature, and possibly decompress, a previously
        generated JSON Web Token (JWT).

        :param str encryptedserial: A JWT previously generated with encrypt().

        :return: Arbitrary user data originally store in token.
        :rtype: dict

        :raises jwcrypto.jwt.JWTExpired: If token expired.
        :raises jwcrypto.jwe.InvalidJWEData: If unable to decrypt or verify
         signature.
        """

        # Decrypt token
        encrypted = JWT()
        encrypted.leeway = self.leeway_s
        encrypted.deserialize(encryptedserial, key=self.encryptkey)

        encryptedclaims = loads(encrypted.claims)
        signedserial = encryptedclaims['dta']

        # Verify token signature
        signed = JWT()
        signed.leeway = self.leeway_s
        signed.deserialize(signedserial, key=self.signkey)

        signedclaims = loads(signed.claims)
        dataserial = signedclaims['dta']

        # Decompress user data
        cps = signedclaims['cps']
        if cps:
            compressed = b64decode(dataserial.encode(encoding='ascii'))
            dataserial = decompress(compressed).decode(encoding='utf-8')

        # Deserialize user data
        data = loads(dataserial)

        return data

    @classmethod
    def validate(cls, token):
        """
        Validate that the given token is a valid JWT token.

        :return: The JWT token.
        :rtype: str

        :raises: ValueError if contents are not a valid JWT token.
        """
        if not cls.JWT_REGEX.match(token):
            raise ValueError('Invalid JWT token')

        return token

    @classmethod
    def generate(cls, size):
        """
        Generate a new symmetric key for encryption or signing.

        This generates a key using key type "kty" "oct" (Octet sequence).

        See RFC7518, Section 6.4:

            https://tools.ietf.org/html/rfc7518#section-6.4

        .. note::

           Key is generated without the base64 padding, so in order to retrieve
           the bytes of the key issue the following:

           ::

              base64.urlsafe_b64decode(key + '=' * (4 - len(key) % 4))

        :param int size: Size of the key to generate in bits.

        :return: The newly generated key as a base64url encoding of the octet
         sequence (bytes sequence, or blob) containing the key value.
        :rtype: str
        """
        return loads(JWK.generate(kty='oct', size=size).export())['k']


if __name__ == '__main__':

    print(
        '1. Craft a session.\n'
        '2. Generate a new encryption or signing key.\n'
    )
    action = int(input('What do you need? '))
    assert action in [1, 2], 'Choose a valid action'

    if action == 1:
        issuer = input('Issuer: ')
        signkey = input('Signing key: ')
        encryptkey = input('Encryption key: ')
        data = loads(input('Data (JSON): '))
        expires_in_s = int(input('Expires in (s): '))

        sessionmgr = JWTPie(
            issuer=issuer,
            signkey=signkey,
            encryptkey=encryptkey,
        )
        print('\nYour session:\n')
        print(sessionmgr.encrypt(data, expires_in_s=expires_in_s))
        print('\nBye!\n')
        exit(0)

    if action == 2:
        size = int(input('Size: '))
        print('\nYour key:\n')
        print(JWTPie.generate(size))
        print('\nBye!\n')
        exit(0)

    assert False, 'End of actions'


__all__ = [
    'JWTPie',
    'JWTExpired',
    'JWTInvalid',
]
