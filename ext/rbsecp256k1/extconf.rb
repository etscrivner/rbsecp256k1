require 'mkmf'

# OpenSSL flags
print("checking for OpenSSL\n")
results = pkg_config('openssl')
abort "missing openssl pkg-config information" unless results[1]

# Require that libsecp256k1 be installed using `make install` or similar.
print("checking for libsecp256k1\n")
results = pkg_config('libsecp256k1')
abort "missing libsecp256k1" unless results[1]

# Check if we have the libsecp256k1 recoverable signature header.
have_header('secp256k1_recovery.h')

# Check if we have EC Diffie-Hellman functionality
have_header('secp256k1_ecdh.h')

create_makefile('rbsecp256k1')
