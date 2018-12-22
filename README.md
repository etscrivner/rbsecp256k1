# rbsecp256k1

[![Build Status](https://travis-ci.com/etscrivner/rbsecp256k1.svg?branch=master)](https://travis-ci.com/etscrivner/rbsecp256k1)

Compiled Ruby extension gem for [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

## Requirements

You'll need to have compiled and installed [libsecp256k1](https://github.com/bitcoin-core/secp256k1) from source. You'll
also need the OpenSSL development bindings.

## Examples

You should now be able to use the gem as expected:

```ruby
require 'rbsecp256k1'
ctx = Secp256k1::Context.new
key_pair = ctx.generate_key_pair

puts Secp256k1::Util.bin_to_hex(key_pair.public_key.as_uncompressed)
puts Secp256k1::Util.bin_to_hex(key_pair.public_key.as_compressed)

sig = ctx.sign(key_pair.private_key, "test message")
puts Secp256k1::Util.bin_to_hex(sig.der_encoded)

if ctx.verify(sig, key_pair.public_key, "test message")
  puts "Valid"
else
  puts "Invalid"
end
```

Similarly you can start with existing key and signature data:

```ruby
require 'rbsecp256k1'
ctx = Secp256k1::Context.new
public_key = ctx.public_key_from_data("\x02/dUQ|\x82\x11r\xFA\xF97\x1F\x95\xD1:\xBC\xE2v\xB2A]\xCB~:\xD7'\e\xBF\xEDjC\x9B")
sig = ctx.signature_from_der_encoded("0D\x02 <\xC6\x7F/\x921l\x89Z\xFBs\x89p\xEE\x18u\x8B\x92\x9D\xA6\x84\xC5Y<t\xB7\xF1\f\xEE\f\x81J\x02 \t\"\xDF]\x1D\xA7W@^\xAAokH\b\x00\xE2L\xCF\x82\xA3\x05\x1E\x00\xF9\xFC\xB19\x0F\x93|\xB1f")

puts Secp256k1::Util.bin_to_hex(public_key.as_uncompressed)
puts Secp256k1::Util.bin_to_hex(public_key.as_compressed)

if ctx.verify(sig, public_key, "test message")
  puts "Valid"
else
  puts "Invalid"
end
```

## Development

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

If you have installed libsecp256k1 but the gem cannot find it. Ensure you have
run `ldconfig` so that your library load paths have been updated.

### Mac OS

When running the `ruby extconf.rb` step, if building on Mac OS with openssl
installed via homebrew it may be helpful to specify the location of your openssl
library: `PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig" ruby extconf.rb`.
