<!--
SPDX-FileCopyrightText: 2026 Eric Scrivner (@etscrivner)
SPDX-FileCopyrightText: 2026 Afri Blanck (@l5yth)
SPDX-License-Identifier: Unlicense
-->

rbsecp256k1 version 6.0.2 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

This is a security and bugfix release covering native object construction,
copying, memory management, and dependency verification. It also fixes
Schnorr signing for arbitrary-length messages and bundles libsecp256k1 0.8.0.

* Invalid native object construction and use now raise Ruby exceptions instead
  of exposing uninitialized native data or aborting the process.
* Contexts, keys, keypairs, and signatures support independent native copies
  through `dup` and `clone`. Shared secrets cannot be copied. Use the documented
  factories to construct keys and signatures; direct construction is rejected.
* Native pointers remain valid across Ruby garbage collection and compaction.
  Failed factories release and invalidate their native payloads before raising,
  and Ruby wrapper allocation failures do not orphan native buffers.
* DER serialization uses the correct native length type on Windows. Native
  secret buffers are erased before release, and cached dependency archives are
  verified before extraction.
* Schnorr signing accepts messages of any byte length, including empty messages,
  without implicit hashing, padding, or truncation.

To upgrade:

```
bundle update rbsecp256k1
```

### Library Updates

The following updates were made to the library:

* Bundle libsecp256k1 0.8.0 ([#91](https://github.com/etscrivner/rbsecp256k1/pull/91))
* Fix Schnorr signing for arbitrary-length messages ([#95](https://github.com/etscrivner/rbsecp256k1/pull/95))
* Prevent invalid native construction, implement safe copying, and reject repeated context initialization ([#98](https://github.com/etscrivner/rbsecp256k1/pull/98))
* Fix the DER serialization length type and remove native length narrowing ([#101](https://github.com/etscrivner/rbsecp256k1/pull/101))
* Erase native secret material before release ([#107](https://github.com/etscrivner/rbsecp256k1/pull/107))
* Verify cached dependency archives before extraction ([#108](https://github.com/etscrivner/rbsecp256k1/pull/108))
* Report owned native allocation sizes to Ruby ([#109](https://github.com/etscrivner/rbsecp256k1/pull/109))
* Fix native pointer lifetimes across Ruby allocations and GC ([#110](https://github.com/etscrivner/rbsecp256k1/pull/110))
* Guard null context destruction during cleanup ([#112](https://github.com/etscrivner/rbsecp256k1/pull/112))
* Fix native allocation ordering and invalidate failed factory objects ([#114](https://github.com/etscrivner/rbsecp256k1/pull/114))

### Development Updates

* Document arbitrary-length Schnorr messages and test official BIP-340 vectors ([#96](https://github.com/etscrivner/rbsecp256k1/pull/96))
* Repair fuzz harness iteration and parser coverage ([#102](https://github.com/etscrivner/rbsecp256k1/pull/102))
* Remove unreliable assumptions about individual object collection from GC tests ([#103](https://github.com/etscrivner/rbsecp256k1/pull/103))
* Support Ruby debug symbols in Valgrind runs and update the Docker build environment ([#111](https://github.com/etscrivner/rbsecp256k1/pull/111))
* Add AddressSanitizer and UndefinedBehaviorSanitizer CI coverage and declare the CSV test dependency ([#112](https://github.com/etscrivner/rbsecp256k1/pull/112))
* Build and test Ruby 3.4 and 4.0 on native Windows UCRT, including static-linking fixes ([#113](https://github.com/etscrivner/rbsecp256k1/pull/113))
