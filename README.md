# rbsecp256k1

Native ruby interface for libsecp256k1.

## Building

You'll need to have compiled and installed libsecp256k1 from source.

Run the following to build:

```
bundle install
cd ext/rbsecp256k1
ruby extconf.rb
make
```

### Mac OS

When running the `ruby extconf.rb` step, if building on Mac OS with openssl
installed via homebrew it may be helpful to specify the location of your openssl
library: `PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig" ruby extconf.rb`.

## Testing

After you have built the gem you can run the unit-tests as follows:

```
ruby -Ilib:ext -r rbsecp256k1 -e "priv_key = Secp256k1::PrivateKey.new(Secp256k1.generate_private_key_bytes); ctx = Secp256k1::Context.new; Secp256k1::PublicKey.new(ctx, priv_key)"
```
