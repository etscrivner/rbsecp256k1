[Index](index.md)

Secp256k1::SchnorrSignature
===========================

Secp256k1::SchnorrSignature represents a 64-byte Schnorr signature of a message
of any byte length, including zero.

Class Methods
-------------

#### from_data(schnorr_sig_data)

Loads a new Schnorr signature from the given 64-byte binary
`schnorr_sig_data`. Does not perform any validation on the loaded data.

Instance Methods
----------------

#### serialized

Returns the 64-byte binary `String` of the serialized Schnorr signature.

#### verify(msg, xonly_pubkey)

Returns `true` if the schnorr signature is a valid signing of `msg` with the
private key for `xonly_pubkey`, `false` otherwise.

`msg` must be a Ruby `String` containing the exact bytes passed to signing.
It may have any byte length, including zero. No implicit hashing is performed.

#### ==(other)

Returns `true` if this signature matches `other`.
