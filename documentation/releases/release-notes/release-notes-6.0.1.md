<!--
SPDX-FileCopyrightText: 2026 Eric Scrivner (@etscrivner)
SPDX-FileCopyrightText: 2026 Afri Blanck (@l5yth)
SPDX-License-Identifier: Unlicense
-->

rbsecp256k1 version 6.0.1 is now available.

Please report bugs using the issue tracker at GitHub:

https://github.com/etscrivner/rbsecp256k1/issues

Notable Changes
===============

Security release. No API changes.

* rbsecp256k1 requires rubyzip 3.4 or later. rubyzip before 3.4.0 has a path
  traversal in `Zip::Entry#extract`: GHSA-47m2-wp7j-p9vc (CVE-2026-85396, high).
* Installing 6.0.1 requires Ruby 3.0 or later, as every rubyzip 3.x does.
* The gem declares the Unlicense, the license in `LICENSE`, and ships
  `LICENSE`. Releases up to 6.0.0 declared MIT.
* CI tests Ruby 3.4 and 4.0 on Linux and macOS.

To upgrade:

```
bundle update rbsecp256k1
```

### Library Updates

The following updates were made to the library:

* Updates rubyzip dependency ([#85](https://github.com/etscrivner/rbsecp256k1/pull/85))
* Require rubyzip 3.4 or later (CVE-2026-85396) ([#90](https://github.com/etscrivner/rbsecp256k1/pull/90))
* Correctly declare the Unlicense and ship LICENSE in the gem ([#92](https://github.com/etscrivner/rbsecp256k1/pull/92))

### Development Updates

* Run CI on Ruby 3.4 and 4.0 only ([#87](https://github.com/etscrivner/rbsecp256k1/pull/87))
* Add weekly Dependabot updates for Bundler and GitHub Actions ([#88](https://github.com/etscrivner/rbsecp256k1/pull/88))
* Bump actions/checkout from 3 to 7 ([#89](https://github.com/etscrivner/rbsecp256k1/pull/89))
