# rbsecp256k1

Native ruby interface for libsecp256k1.

## Building

Run the following to build:

```
bundle install
cd ext/rbsecp256k1
ruby extconf.rb
make
```

## Testing

After you have built the gem you can run the unit-tests as follows:

```
ruby -Ilib:ext -r rbsecp256k1 -e "priv_key = Secp256k1::PrivateKey.new(Secp256k1.generate_private_key_bytes); ctx = Secp256k1::Context.new; Secp256k1::PublicKey.new(ctx, priv_key)"
```
