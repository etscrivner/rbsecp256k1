rbsecp256k1 version 6.0.0 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

Schnorr signatures and breaking changes are here!

This is a backwards incompatible release that adds Schnorr signature
support. The method `KeyPair#initialize` was removed in this release and will
therefore break any software that relies on it. This should be the extent of
the breaking changes.

This release adds new classes `SchnorrSignature` and `XOnlyPublicKey` as well
as new context method `Context#sign_schnorr`. The documentation has been
updated to include these classes as well as examples of using Schnorr
signatures.

### Library Updates

The following updates were made to the library:

* Upgrade To Official Release libsecp256k1 v0.2.0 ([#68](https://github.com/etscrivner/rbsecp256k1/pull/68))
* Documentation and Code Cleanup For ECDH ([#69](https://github.com/etscrivner/rbsecp256k1/pull/69))
* Minimize Usage of Static Context ([#70](https://github.com/etscrivner/rbsecp256k1/pull/70))
* [Backwards Incompatible] Refactor KeyPair to use secp256k1_keypair ([#71](https://github.com/etscrivner/rbsecp256k1/pull/71))
* Make PrivateKey#data method instead of attribute ([#72](https://github.com/etscrivner/rbsecp256k1/pull/72))
* Add Support For X-Only Public Keys ([#73](https://github.com/etscrivner/rbsecp256k1/pull/73))
* Add KeyPair#xonly_public_key Method ([#74](https://github.com/etscrivner/rbsecp256k1/pull/74))
* Add Schnorr Signature Support ([#75](https://github.com/etscrivner/rbsecp256k1/pull/75))
* Documentation Overhaul In Preparation For Release ([#76](https://github.com/etscrivner/rbsecp256k1/pull/76))
