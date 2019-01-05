rbsecp256k1 version 4.0.0 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

This release makes major changes to the library in terms of object allocation
and cloning. It removes the cloning of most `secp256k1_context` objects and
opts for the static `secp256k1_context_no_precomp` where it is possible to use
this. This allows for a major restructuring of the library to something more
sensible.

### Library Updates

The following updates were made to the library:

*  Use Static Contexts Where Possible ([#35](https://github.com/etscrivner/rbsecp256k1/pull/35))
