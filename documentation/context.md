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

#### ecdh(point, scalar)

**Requires:** libsecp256k1 was built with the experimental ECDH module.

Takes a `point` ([PublicKey](public_key.md)) and a `scalar` ([PrivateKey](private_key.md)) and returns a new
[SharedSecret](shared_secret.md) containing the 32-byte shared secret. Raises a `RuntimeError` if
the `scalar` is invalid (zero or causes an overflow).

#### generate_key_pair

Generates and returns a new [KeyPair](key_pair.md) using a cryptographically
secure random number generator (CSRNG) provided by OpenSSL.

#### key_pair_from_private_key(private_key_data)

Returns a new [KeyPair](key_pair.md) from the given `private_key_data`. The
`private_key_data` is expected to be a binary string. Raises a `RuntimeError`
if the private key is invalid or key derivation fails.

#### private_key_from_data(private_key_data)

Creates a new [PrivateKey](private_key.md) from `private_key_data`. Raises an `ArgumentError`
if private key is invalid.

#### public_key_from_data(public_key_data)

If `public_key_data` is a valid compressed or uncompressed public key, returns
a new [PublicKey](public_key.md) object corresponding to. The `public_key_data`
is expected to be a binary string.

#### recoverable_signature_from_compact(compact_signature, recovery_id)

**Requires:** libsecp256k1 was build with recovery module.

Attempts to load a [RecoverableSignature](recoverable_signature.md) from the given `compact_signature`
and `recovery_id`. Raises a RuntimeError if the signature data or recovery ID are invalid.

#### sign(private_key, hash32)

Signs the SHA-256 hash given by `hash32` using `private_key` and returns a new
[Signature](signature.md). The `private_key` is expected to be a [PrivateKey](private_key.md)
object and `data` can be either a binary string or text.

#### sign_recoverable(private_key, hash32)

**Requires:** libsecp256k1 was build with recovery module.

Signs the data represented by the SHA-256 hash `hash32` using `private_key` and returns a
new [RecoverableSignature](recoverable_signature.md). The `private_key` is expected to be a [PrivateKey](private_key.md) and
`data` can be either a binary string or text.

#### signature_from_compact(compact_signature)

Parses `compact_signature` and returns a new [Signature](signature.md) object corresponding to
its data. The `compact_signature` is expected to be a binary string. Raises a
`RuntimeError` if the signature data is invalid.

#### signature_from_der_encoded(der_encoded_signature)

Parses `der_encoded_signature` and returns a new [Signature](signature.md) object corresponding
to its data. The `der_encoded_signature` is expected to be a binary string.
Raises a `RuntimeError` if the signature data is invalid.

#### verify(signature, public_key, hash32)

Verifies the given `signature` ([Signature](signature.md)) was signed by
the private key corresponding to `public_key` ([PublicKey](public_key.md)) and signed `hash32`. Returns `true`
if `signature` is valid or `false` otherwise. Note that `data` can be either a
text or binary string.
