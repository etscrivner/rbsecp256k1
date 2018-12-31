[Index](index.md)

Secp256k1::Signature
====================

Secp256k1::Signature represents an ECDSA signature signing the 32-byte SHA-256
hash of some data.

Instance Methods
----------------

#### der_encoded

Returns the DER encoded representation of this signature.

#### compact

Returns the compact 64-byte representation of this signature.

#### normalized

Returns an array containing two elements. The first is a Boolean indicating
whether or not the signature was normalized, false if it was already in lower-S
normal form. The second element is a `Signature` containing the normalized
signature object.

#### ==(other)

Returns `true` if this signature matches `other`.
