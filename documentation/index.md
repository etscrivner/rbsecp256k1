rbsecp256k1 Reference
=====================

Find your topic in the index, or refer to one of the examples below.

Classes and Modules
-------------------

Classes                          | Utilities
:--------------------------------|:--------------------------------
[Context](context.md)            | [Util](util.md)
[KeyPair](key_pair.md)           |
[PublicKey](public_key.md)       |
[PrivateKey](private_key.md)     |
[Signature](signature.md)        |

Glossary
--------

**[Context](context.md)** is a libsecp256k1 library context. It contains
pre-computed tables and values to make ECDSA signing and verification more
efficient.

**[KeyPair](key_pair.md)** is a Secp256k1 elliptic-curve key pair.

**[PublicKey](public_key.md)** is a Secp256k1 public key. It can come in either
compressed or uncompressed format.

**[PrivateKey](private_key.md)** is a 64-byte Secp256k1 private key.

**[Signature](signature.md)** is an ECDSA signature of the SHA-256 message hash
of a piece of data.

Examples
--------

### 1. Creating a libsecp256k1 context

This example demonstrates how to create a new libsecp256k1 context. This is the
first step of using this library:

```ruby
context = Secp256k1::Context.new
# => #<Secp256k1::Context:0x0000559b0bd8f5d0>
```

### 2. Generating a key pair

This example shows how to generate a new public-private key pair:

```ruby
context = Secp256k1::Context.new
key_pair = context.generate_key_pair
# => #<Secp256k1::KeyPair:0x0000559b0bc876b0 @public_key=#<Secp256k1::PublicKey:0x0000559b0bc876d8>, @private_key=#<Secp256k1::PrivateKey:0x0000559b0bc87700 @data="\r\xA7\xB3<\x92\xCDw\xC1\xDB\xEB[BB;=\x80\xB83\xA8]\x06\xD9\x90\xF8v\xFFi\xF0/\x1E\x96\xF9">>
```

### 3. Getting compressed and uncompressed public key representations

This example shows how to generate compressed and uncompressed public keys:

```ruby
context = Secp256k1::Context.new
key_pair = context.generate_key_pair

# 1. Get the binary representation of compressed public key
key_pair.public_key.compressed
# => "\x03D\x88\xD6 3|3\x836\xCB(\x9CW%\xF4T\xB7\xCD\x8AF T\xE7\xE8\xCE\xB0\xC7c{\xE2:\xFE"

# 2. Show hex representation of compressed public key
Secp256k1::Util.bin_to_hex(key_pair.public_key.compressed)
# => "034488d620337c338336cb289c5725f454b7cd8a462054e7e8ceb0c7637be23afe"

# 3. Get the binary representation of uncompressed public key
key_pair.public_key.uncompressed
# => "\x04D\x88\xD6 3|3\x836\xCB(\x9CW%\xF4T\xB7\xCD\x8AF T\xE7\xE8\xCE\xB0\xC7c{\xE2:\xFE XRew\x1F\e\x05\xC8\xDC\xA7\xE3\x8C\xBD\x91s?\xFCW\xD5\xB3\xA8aaCCG\xD4\x94m\xA5c"

# 4. Show hex representation of uncompressed public key
Secp256k1::Util.bin_to_hex(key_pair.public_key.uncompressed)
# => "044488d620337c338336cb289c5725f454b7cd8a462054e7e8ceb0c7637be23afe20585265771f1b05c8dca7e38cbd91733ffc57d5b3a86161434347d4946da563"
```

### 3. Signing a message

This example shows how to sign a message using your private key:

```ruby
context = Secp256k1::Context.new
key_pair = context.generate_key_pair

signature = context.sign(key_pair.private_key, "test message")
# => #<Secp256k1::Signature:0x0000559b0bc79358>
```

Note that signed data can be an ASCII or UTF-8 string or any arbitrary array of
bytes.

### 4. Getting DER and Compact signature encodings

This example shows you how to get the DER encoded and compact encoded
representations of a signature:

```ruby
context = Secp256k1::Context.new
key_pair = context.generate_key_pair

signature = context.sign(key_pair.private_key, "test message")

# 1. Get the compact binary representation
signature.compact
# => "\xAB#e6_\x866\e\xAC\e\x92W\xC8a\x84N\xD4\xB6\x88\xF8\xEE\xDF\xFBC\xE8j\xB2\xF0\x10\xB8\xA0\x89\x13L\e\x9E\x91cB\xD7\xAC\x11\xF7\x02,Y&TM\xA5zp\xFD\xB3\xB1\xDCIV\xBB\\\xAF\x16@\xFC\x00"

# 2. Get the compact hex representation
Secp256k1::Util.bin_to_hex(signature.compact)
# => "ab2365365f86361bac1b9257c861844ed4b688f8eedffb43e86ab2f010b8a089134c1b9e916342d7ac11f7022c5926544da57a70fdb3b1dc4956bb5caf1640fc00"

# 3. Get the DER binary representation
signature.der_encoded
# => "0E\x02!\x00\xAB#e6_\x866\e\xAC\e\x92W\xC8a\x84N\xD4\xB6\x88\xF8\xEE\xDF\xFBC\xE8j\xB2\xF0\x10\xB8\xA0\x89\x02 \x13L\e\x9E\x91cB\xD7\xAC\x11\xF7\x02,Y&TM\xA5zp\xFD\xB3\xB1\xDCIV\xBB\\\xAF\x16@\xFC"

# 4. Get the DER hex representation
Secp256k1::Util.bin_to_hex(signature.der_encoded)
# => "3045022100ab2365365f86361bac1b9257c861844ed4b688f8eedffb43e86ab2f010b8a0890220134c1b9e916342d7ac11f7022c5926544da57a70fdb3b1dc4956bb5caf1640fc"
```

### 5. Verifying a signature

This example shows how to verify a signature using a public key:

```ruby
context = Secp256k1::Context.new
key_pair = context.generate_key_pair

signature = context.sign(key_pair.private_key, "test message")

# 1. Verify signature against matching message
context.verify(signature, key_pair.public_key, "test message")
# => true

# 2. Verify signature against different message
context.verify(signature, key_pair.public_key, "other message")
# => false
```

### 6. Loading a key pair from private key data

This example shows how to load a key pair from raw binary private key data:

```ruby
context = Secp256k1::Context.new

key_pair = context.key_pair_from_private_key("I\nX\x85\xAEz}\n\x9B\xA4\\\x81)\xD4\x9Aq\xFDH\t\xBE\x8EP\xC5.\xC6\x1F7-\x86\xA0\xCB\xF9")
# => #<Secp256k1::KeyPair:0x0000559b0bbf9a90 @public_key=#<Secp256k1::PublicKey:0x0000559b0bbf9ab8>, @private_key=#<Secp256k1::PrivateKey:0x0000559b0bbf9ae0 @data="I\nX\x85\xAEz}\n\x9B\xA4\\\x81)Ԛq\xFDH\t\xBE\x8EP\xC5.\xC6\u001F7-\x86\xA0\xCB\xF9">>
```

### 7. Loading a public key from binary data

This example shows how to load a public key from binary data:

```ruby
context = Secp256k1::Context.new

# 1. Load public key from uncompressed pubkey
public_key = context.public_key_from_data("\x04$\xA2\xE7\xBB1\xC4|tN\xE6\xE4J-\xED\x9A[\xAFf-<\x14\x84^QQ\"\x14\xC3\x91\xE4\xF2\xB5\xEEEj\xAB\xD9\xFE\b\e7Zk\xC5{k\x12\xE3\xEA\xA2\xA5\xD7\xC1\xA5&\xE5|:K\xA9 X\xA3\x90")
# => #<Secp256k1::PublicKey:0x0000559b0bdc72f0>

# 2. Load public key from compressed pubkey
public_key = context.public_key_from_data("\x02$\xA2\xE7\xBB1\xC4|tN\xE6\xE4J-\xED\x9A[\xAFf-<\x14\x84^QQ\"\x14\xC3\x91\xE4\xF2\xB5")
# => #<Secp256k1::PublicKey:0x0000559b0bdd3668>
```

### 8. Loading a DER or compact encoded signature

This example shows how to load signatures from binary data:

```ruby
context = Secp256k1::Context.new

# 1. From DER encoded signature
signature = context.signature_from_der_encoded("0D\x02 <\xC6\x7F/\x921l\x89Z\xFBs\x89p\xEE\x18u\x8B\x92\x9D\xA6\x84\xC5Y<t\xB7\xF1\f\xEE\f\x81J\x02 \t\"\xDF]\x1D\xA7W@^\xAAokH\b\x00\xE2L\xCF\x82\xA3\x05\x1E\x00\xF9\xFC\xB19\x0F\x93|\xB1f")
# => #<Secp256k1::Signature:0x0000559b0b823d58>

# 2. From compact signature
signature = context.signature_from_compact("<\xC6\x7F/\x921l\x89Z\xFBs\x89p\xEE\x18u\x8B\x92\x9D\xA6\x84\xC5Y<t\xB7\xF1\f\xEE\f\x81J\t\"\xDF]\x1D\xA7W@^\xAAokH\b\x00\xE2L\xCF\x82\xA3\x05\x1E\x00\xF9\xFC\xB19\x0F\x93|\xB1f\x00")
# => #<Secp256k1::Signature:0x0000559b0bdcaa68>
```
