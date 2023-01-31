[Index](index.md)

Secp256k1::XOnlyPublicKey
=========================

Secp256k1::XOnlyPublicKey represents an x-only public key version of a public key.

See: [KeyPair](key_pair.md)

Class Methods
-------------

#### from_data(xonly_public_key_serialized)

Parses the 32-byte serialized binary `xonly_public_key_serialized` and creates
and returns a new x-only public key from it. Raises a
`Secp256k1::DeserializationError` if the given x-only public key data is
invalid.

Instance Methods
----------------

#### serialized

Serializes the `XOnlyPublicKey` into a 32-byte binary `String`.

#### ==(other)

Return `true` if this x-only public key matches `other`.
