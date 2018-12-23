[Index](index.md)

Secp256k1::Context
==================

Secp256k1::Context represents a libsecp256k1 context object. Contexts are
thread-safe and initialization is expensive, so a single context should be used
for multiple operations as much as possible.

Initializers
------------

#### new

Returns a newly initialized libsecp256k1 context. The context is randomized at
initialization.

Instance Methods
----------------

#### generate_key_pair

Generates and returns a new [KeyPair](key_pair.md) using a cryptographically
secure random number generator (CSRNG) provided by OpenSSL.

#### key_pair_from_private_key(private_key_data)

Returns a new [KeyPair](key_pair.md) from the given `private_key_data`. The
`private_key_data` is expected to be a binary string. Raises a `RuntimeError`
if the private key is invalid or key derivation fails.

#### public_key_from_data(public_key_data)

If `public_key_data` is a valid compressed or uncompressed public key, returns
a new [PublicKey](public_key.md) object corresponding to. The `public_key_data`
is expected to be a binary string.

#### sign(private_key, data)

Signs the SHA-256 hash of the given `data` using `private_key` and returns a
new [Signature](signature.md). The `private_key` is expected to be a [PrivateKey](private_key.md)
object and `data` can be either a binary string or text.

#### signature_from_compact(compact_signature)

Parses `compact_signature` and returns a new [Signature](signature.md) object corresponding to
its data. The `compact_signature` is expected to be a binary string. Raises a
`RuntimeError` if the signature data is invalid.

#### signature_from_der_encoded(der_encoded_signature)

Parses `der_encoded_signature` and returns a new [Signature](signature.md) object corresponding
to its data. The `der_encoded_signature` is expected to be a binary string.
Raises a `RuntimeError` if the signature data is invalid.

#### verify(signature, public_key, data)

Verifies the given `signature` (type: [Signature](signature.md)) was signed by
the private key corresponding to `public_key` (type: [PublicKey](public_key.md)) and signed `data`. Returns `true`
if `signature` is valid or `false` otherwise. Note that `data` can be either a
text or binary string.
