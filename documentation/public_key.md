[Index](index.md)

Secp256k1::PublicKey
====================

Secp256k1::PublicKey represents the public key part of a public-private key pair.

See: [KeyPair](key_pair.md)

Initializers
------------

#### new(context, private_key)

Creates a new public key derived from `private_key` (type: [PrivateKey](private_key.md)) using
`context` (type: [Context](context.md)).

Instance Methods
----------------

#### as_compressed

Returns the binary compressed representation of this public key.

#### as_uncompressed

Returns the binary uncompressed representation of this public key.
