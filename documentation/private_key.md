[Index](index.md)

Secp256k1::PrivateKey
=====================

Secp256k1::PrivateKey represents the private key part of a public-private key pair.

Initializers
------------

#### new(context, private_key_data)

Initializes the private key with the `in_context` and provided 32-byte binary
string `private_key_data`.

Class Methods
-------------

#### generate(context)

Generates a new private key with `in_context`.
