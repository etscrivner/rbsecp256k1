# Unreleased

## Native object lifecycle safety (SEC-001)

Keys, signatures, and shared secrets must be created through the documented
factory methods. Calling `new` or `allocate` on these classes now raises
`TypeError`, including on subclasses. This prevents access to uninitialized
native memory and invalid cryptographic objects that could terminate Ruby.

Keys and signatures support safe `dup` and `clone` with independently owned
native storage. Recoverable signatures also clone their owned context. Private
key and keypair copies contain additional copies of secret material. Shared
secrets still reject copying with `TypeError`. Direct `new` and `allocate`
remain rejected. Contexts also support independent native copying:

```ruby
context = Secp256k1::Context.create
key_pair = context.generate_key_pair
public_key = key_pair.public_key

# Independent native key storage:
another_public_key = public_key.dup
another_key_pair = key_pair.clone

# Copies the existing context state with independent native ownership:
another_context = context.dup

# For fresh randomization instead:
newly_randomized_context = Secp256k1::Context.create
```

`Context.new` and the documented context factories continue to work. Context
copies preserve Ruby copy semantics: `clone` preserves frozen state,
while `dup` returns an unfrozen copy. Cloning does not provide fresh
randomization. Copying an uninitialized context raises `Secp256k1::Error`.

Native operations on a context whose initialization was skipped now raise
`Secp256k1::Error` with `context is not initialized`. Context subclasses must
call `super` from their initializers before invoking native operations.

Calling `initialize` again on an initialized context now raises
`Secp256k1::Error` with `context is already initialized`, preserving the
existing context and preventing the former native allocation leak (SEC-005).
Create a new context when another initialization is required.
