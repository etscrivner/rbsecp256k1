rbsecp256k1 version 5.1.0 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

This is a bugfix release that includes major updates to older dependencies
including ruby-zip and libsecp256k1. These older dependencies were breaking
ruby 3.0 builds. Travis CI has also been replaced in favor of GitHub Actions.

### Library Updates

The following updates were made to the library:

* upgrade rubyzip ([#50](https://github.com/etscrivner/rbsecp256k1/pull/50))
* Upgrade bitcoin-core/secp256k1 to latest HEAD ([#55](https://github.com/etscrivner/rbsecp256k1/pull/55))
* ci: replace travis with github actions ([#56](https://github.com/etscrivner/rbsecp256k1/pull/56))
