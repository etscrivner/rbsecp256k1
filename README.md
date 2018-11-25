# rbsecp256k1

Native ruby interface for libsecp256k1.

## Building

You'll need to have compiled and installed libsecp256k1 from source.

Run the following to build:

```
gem build rbsecp256k1.gemspec
```

This will build the gem file, now you need to install:

```
gem install rbsecp256k1-X.X.X.gem
```

You should now be able to use the gem by requiring it in the console:

```ruby
require 'rbsecp256k1'
priv_key = Secp256k1::PrivateKey.new(Secp256k1.generate_private_key_bytes)
ctx = Secp256k1::Context.new
pub_key = Secp256k1::PublicKey.new(ctx, priv_key)
```

### Linux

If you have installed libsecp256k1 but the gem cannot find it. Ensure you have
run `ldconfig` so that your library load paths are the latest.

### Mac OS

When running the `ruby extconf.rb` step, if building on Mac OS with openssl
installed via homebrew it may be helpful to specify the location of your openssl
library: `PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig" ruby extconf.rb`.