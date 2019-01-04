Release Process
===============

### Verify Builds

* Update version in `lib/rbsecp256k1/version.rb`
* Building against libsecp256k1 without any modules works (`make clean && make test`)
* Building against libsecp256k1 with recovery module works (`make clean &&  make test WITH_RECOVERY=0`)
* Building against libsecp256k1 with ECDH module works (`make clean && make test WITH_ECDH=0`)
* Building against libsecp256k1 with both modules works (`make clean && make test WITH_RECOVERY=0 WITH_ECDH=0`)

### Cutting A Release

First you'll need to checkout a new branch and add release notes:

```
git checkout release-${VERSION}
git add documentation/releases/release-notes/release-notes-${VERSION}.md
```

Once the above branch has been merged you'll need to cut a release tag:

```
git checkout appropriate branch for release series
git tag -s v${VERSION} HEAD
git push origin --tags
```

Finally, you'll need to add a new release for the given version to GitHub
containing the following a link to the release notes:

```
rbsecp256k1 version ${VERSION} is now available.

For release notes see:

https://github.com/etscrivner/rbsecp256k1/blob/master/documentation/releases/release-notes/release-notes-${VERSION}.md
```

### Pushing Gem

Once the release has been published to GitHub, you should push up a new
version of the gem.

```
make gem
gem push rbsecp256k1-${VERSION}.gem
```
