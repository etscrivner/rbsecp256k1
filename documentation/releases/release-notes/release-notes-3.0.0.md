rbsecp256k1 version 3.0.0 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

This release now bundles libsecp256k1 with the gem and downloads and installs
it at compile time. It also includes some minor improvements and bugfixes.

### Library Updates

The following updates were made to the library:

* Bundle libsecp256k1 with the gem ([`a706068`](https://github.com/etscrivner/rbsecp256k1/commit/a7060684fdb1028a559423795ba6e9327ef89f3b))

### Bug Fixes and Improvements

The following bug fixes and improvements are included in this version:

* Add more input validation ([`e713f69`](https://github.com/etscrivner/rbsecp256k1/commit/e713f6949de51b328307eca1d4d02dcfc77bee18))
* Add fuzzing tests ([`41f5201`](https://github.com/etscrivner/rbsecp256k1/commit/41f52010972f9d0a7aad2dac19fb24d5e2caf7af))
