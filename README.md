# rbsecp256k1

[![Build Status](https://travis-ci.com/etscrivner/rbsecp256k1.svg?branch=master)](https://travis-ci.com/etscrivner/rbsecp256k1) [![Gem Version](https://badge.fury.io/rb/rbsecp256k1.svg)](https://badge.fury.io/rb/rbsecp256k1)

Compiled Ruby extension gem for [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

[Documentation](documentation/index.md)

## Installation

### Requirements

You'll need to have compiled and installed [libsecp256k1](https://github.com/bitcoin-core/secp256k1) from source. You'll
also need the OpenSSL development bindings. More info is available in the Linux
and macOS sections below.

### Linux

Install the dependencies for building libsecp256k1 and this library:

```
sudo apt-get install build-essential automake pkg-config libtool \
  libffi-dev libssl-dev libgmp-dev python-dev
```

**NOTE:** If you have installed libsecp256k1 but the gem cannot find it. Ensure
you have run `ldconfig` so that your library load paths have been updated.

### macOS

Dependencies for building libsecp256k1 and this library:

```
brew install libtool pkg-config gmp libffi
```

## Examples

You should now be able to use the gem as expected:

```ruby
require 'rbsecp256k1'
ctx = Secp256k1::Context.new
key_pair = ctx.generate_key_pair

puts Secp256k1::Util.bin_to_hex(key_pair.public_key.uncompressed)
puts Secp256k1::Util.bin_to_hex(key_pair.public_key.compressed)

sig = ctx.sign(key_pair.private_key, "test message")
puts Secp256k1::Util.bin_to_hex(sig.der_encoded)

ctx.verify(sig, key_pair.public_key, "test message")
# => true
```

Similarly you can start with existing key and signature data:

```ruby
require 'rbsecp256k1'
ctx = Secp256k1::Context.new
public_key = ctx.public_key_from_data("\x02/dUQ|\x82\x11r\xFA\xF97\x1F\x95\xD1:\xBC\xE2v\xB2A]\xCB~:\xD7'\e\xBF\xEDjC\x9B")
sig = ctx.signature_from_der_encoded("0D\x02 <\xC6\x7F/\x921l\x89Z\xFBs\x89p\xEE\x18u\x8B\x92\x9D\xA6\x84\xC5Y<t\xB7\xF1\f\xEE\f\x81J\x02 \t\"\xDF]\x1D\xA7W@^\xAAokH\b\x00\xE2L\xCF\x82\xA3\x05\x1E\x00\xF9\xFC\xB19\x0F\x93|\xB1f")

puts Secp256k1::Util.bin_to_hex(public_key.uncompressed)
puts Secp256k1::Util.bin_to_hex(public_key.compressed)

ctx.verify(sig, public_key, "test message")
# => true
```

## Development

### Cloning

To clone the repository and its submodules you'll need to the following:

```
git clone --recurse-submodules git@github.com:etscrivner/rbsecp256k1.git
```

### Installing libsecp256k1

libsecp256k1 is vendored into this repository as a submodule. To build and
install it you can run:

```
make deps
```

### Setup

Development is largely facilitated by a makefile. After download you should run
the following command to set up your local environment:

```
make setup
```

### Compiling Extension

To compile the extension gem run the following (this is required to run tests):

```
make build
```

### Running Tests

```
make test
```

### Building Gem

```
make gem
```

### Installing Gem Locally

To install the gem locally and verify builds you can run:

```
make install
```

### Uninstall Gem Locally

You can similarly uninstall the local gem by running the following:

```
make uninstall
```

### Linux

Dependencies for building library and its dependencies:

```
sudo apt-get install build-essential automake pkg-config libtool \
  libffi-dev libssl-dev libgmp-dev python-dev
```

**NOTE:** If you have installed libsecp256k1 but the gem cannot find it. Ensure
you have run `ldconfig` so that your library load paths have been updated.

### macOS

Dependencies for building library and its dependencies:

```
brew install libtool pkg-config gmp libffi
```

When running the `ruby extconf.rb` step, if building on Mac OS with openssl
installed via homebrew it may be helpful to specify the location of your openssl
library: `PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig" ruby extconf.rb`.
