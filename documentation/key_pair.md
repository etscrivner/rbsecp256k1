[Index](index.md)

Secp256k1::KeyPair
==================

Secp256k1::KeyPair represents a public-private Secp256k1 key pair.

Instance Methods
----------------

#### public_key

Returns the [PublicKey](public_key.md) part of this key pair.

#### xonly_public_key

Returns the [XOnlyPublicKey](xonly_public_key.md).

#### private_key

Returns the [PrivateKey](private_key.md) part of this key pair.

#### ==(other)

Returns `true` if the `other` has the same public and private key.
