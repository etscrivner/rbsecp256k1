[Index](index.md)

Secp256k1::SchnorrSignature
===========================

Secp256k1::SchnorrSignature represents an Schnorr signature signing a 32-byte message.

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

#### ==(other)

Returns `true` if this signature matches `other`.
