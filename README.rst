===============================================
jwtpie - Easily encrypt and decrypt JWT tokens
===============================================

jwtpie is a highly opinionated library that makes encrypting and decrypting
JWT tokes super easy. Perfect addition to your API backends.

jwtpie does the following:

- Serialize and possibly compress your data.
- Generate a signed JWT token with your serialized data.
- Generate an encrypted JWT token with your signed JWT token.

And also:

- Decrypt your encrypted JWT token, and validate it is still valid.
- Verify signature of decrypted JWT token and validate it is still valid.
- De-serialize and possibly decompress your data.


Install
=======

.. code-block:: sh

    pip3 install jwtpie

Optionally, install either orjson_ (preferred) or ujson_ (good) for a faster
JSON decoding:

.. code-block:: sh

    pip3 install orjson

Or ...

.. code-block:: sh

    pip3 install ujson


.. _orjson: https://github.com/ijl/orjson
.. _ujson: https://github.com/ultrajson/ultrajson


Usage
=====

.. code-block:: python3

    >>> from jwtpie import JWTPie
    >>> mgr = JWTPie()
    >>> token = mgr.encrypt({
    ...    'user': 'jane_doe@anonymous.io',
    ...    'name': 'Jane Doe',
    })
    >>> token
    'eyJhbGciO[.........]iJBMjU2S1ldbM'
    >>> mgr.decrypt(token)
    {
        'user': 'jane_doe@anonymous.io',
        'name': 'Jane Doe',
    }

So easy.

The above will generate a new signing and encryption key on-the-fly. If the
process is restarted or killed, the key will be lost and all tokens generated
with it will no longer be decryptable.

To allow to decode previously generated tokens pass the signing and encryption
key in the constructor:

.. code-block:: python3

    >>> mgr = JWTPie(
    ...     issuer='myapp',
    ...     signkey='YOUR PRIVATE SIGNING KEY',
    ...     encryptkey='YOUR PRIVATE ENCRYPTION KEY',
    ...     expiration_s=1209600,  # In seconds. 60 * 60 * 24 * 14 = Two weeks
    ... )

To generate a private key execute:

.. code-block:: python3

    >>> from jwtpie import JWTPie
    >>> size = 256
    >>> JWTPie.generate(size)
    noOIbGe_WLbTfrLIH_grNu0bf5u8Xx-bERELm2TLRaM

Or launch the interactive wizard::

    python3 -m jwtpie

**THIS IS A SECRET!**

Save it in your secret management system!

- Do not hard code it.
- Do not commit it to version control.
- Never log it.

jwtpie is opinionated because it selects the signing and encryption algorithms
for you. If you need to change this or change advanced parameters like the
leeway please read the documentation if the docstring of the JWTPie class.


Repository
==========

    https://github.com/kuralabs/jwtpie


Acknowledgements
================

JWTPie is just an easy to use abstraction layer built on top of the great
JWCrypto_ library. JWCrypto does the actual work of creating and verifying the
tokens according to the JWT specification. JWCrypto is itself built on top of
the secure cryptography_ library.

.. _JWCrypto: https://github.com/latchset/jwcrypto
.. _cryptography: https://github.com/pyca/cryptography


Changelog
=========

1.0.0 (2021-06-01)
------------------

New
~~~

- Initial release.


License
=======

.. code-block:: text

   Copyright (C) 2016-2021 KuraLabs S.R.L

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.
