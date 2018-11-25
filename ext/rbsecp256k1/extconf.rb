require 'mkmf'

# OpenSSL flags
print("Looking for OpenSSL")
results = pkg_config('openssl')
abort "missing openssl pkg-config information" unless results[1]

# Require that libsecp256k1 be installed using `make install` or similar.
print("Looking for libsecp256k1")
results = pkg_config('libsecp256k1')
abort "missing libsecp256k1" unless results[1]

create_makefile('rbsecp256k1')
