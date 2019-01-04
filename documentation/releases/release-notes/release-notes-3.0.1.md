rbsecp256k1 version 3.0.1 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

This is a minor release that improves the macOS build experience by
automatically detecting Homebrew installed OpenSSL (so long as it is installed
using the default directory structure).

### Bug Fixes and Improvements

The following bug fixes and improvements are included in this version:

* Automatically Infer Homebrew OpenSSL Path On MacOS ([`09c8a70`](https://github.com/etscrivner/rbsecp256k1/commit/09c8a70d138a5f6f9fd864cd6668ba30d0e637ab))
