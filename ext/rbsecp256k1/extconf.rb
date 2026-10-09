# frozen_string_literal: true

require 'mkmf'
require_relative 'secp256k1_recipe'

if with_config('system-library')
  # Require that libsecp256k1 be installed using `make install` or similar.
  message("checking for libsecp256k1\n")
  results = pkg_config('libsecp256k1')
  abort "missing libsecp256k1" unless results && results[1]
else
  # Build the libsecp256k1 dependency
  recipe = Secp256k1Recipe.new
  recipe.cook
  recipe.activate

  # Need to add paths to includes and libraries for library for build
  append_cflags(
    [
      "-I#{recipe.path}/include",
      "-fPIC",
      "-Wno-undef",
      "-Wall"
    ]
  )
  # Since libsecp256k1 v0.4.0, consumers of the static library on Windows must
  # define SECP256K1_STATIC before including secp256k1.h.
  append_cflags("-DSECP256K1_STATIC") if RUBY_PLATFORM =~ /mingw|mswin/
  append_ldflags(
    [
      "-Wl,--no-as-needed"
    ]
  )
  # rubocop:disable Style/GlobalVars
  $LIBPATH = ["#{recipe.path}/lib"] | $LIBPATH
  # rubocop:enable Style/GlobalVars

  # Also need to make sure we add the library as part of the build
  have_library("secp256k1")
  have_library("gmp")
end

# Reject ABI-incompatible pointer arguments when the compiler supports it.
append_cflags('-Werror=incompatible-pointer-types')

# Sanity check for the basic library
have_header('secp256k1.h')

# Check if we have the libsecp256k1 recoverable signature header.
have_header('secp256k1_recovery.h') if WITH_RECOVERY

# Check if we have EC Diffie-Hellman functionality
have_header('secp256k1_ecdh.h')

# Check if we have Schnorr signatures
have_header('secp256k1_schnorrsig.h')

# Check if we have extra keys module
have_header('secp256k1_extrakeys.h')

# See: https://guides.rubygems.org/gems-with-extensions/
create_makefile('rbsecp256k1/rbsecp256k1')
