rbsecp256k1 version 2.0.0 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

This release contains significant bug fixing and adds support for recovery and
ECDH modules optionally provided by lisecp256k1. Note that ECDH is an
experimental module and likely not safe for production use.

### Bug Fixes and Improvements

The following bug fixes and improvements are included in this version:

* Use `TypedData_*` methods for object access and creation ([`2acf4b1`](https://github.com/etscrivner/rbsecp256k1/commit/2acf4b1b932c9ad5b5907aff590d3a797872a94b))
* Fix memory leak ([`237afcf`](https://github.com/etscrivner/rbsecp256k1/commit/237afcfa231143af86e9237ada4d4a580d2d7126))
* Clone contexts to avoid lifetime issues ([`1b87ab5`](https://github.com/etscrivner/rbsecp256k1/commit/1b87ab503f65a06e165590dfc7b2102f5d60cef3))

### Library Updates

The following updates were made to the library:

* Add support for recovery module ([`3d919fe`](https://github.com/etscrivner/rbsecp256k1/commit/3d919fe4add7a4613be3013ede7db3e1514af029))
* Add support for ECDH module ([`0968e4f`](https://github.com/etscrivner/rbsecp256k1/commit/0968e4f711ffcc8c5da2c6e184eb73d6c974800b))
* Add support for signature normalization ([`9fa8d04`](https://github.com/etscrivner/rbsecp256k1/commit/9fa8d041e34779a34c9331c9140ae541aea72035))
* Require users to now compute and provide their own SHA-256 hashes ([`744398a`](https://github.com/etscrivner/rbsecp256k1/commit/744398aa0ac96c5c76862367cf041d3361d968d2))
* Replace `PublicKey#as_*` methods ([`7b660fe`](https://github.com/etscrivner/rbsecp256k1/commit/7b660fe118163a8e22c58d70021e7f519d7b5edc))
* Remove `PublicKey#initialize` and `PrivateKey#initialize` ([`769e8db`](https://github.com/etscrivner/rbsecp256k1/commit/769e8db949df2967025dd121a32ce35b3655ba96))
