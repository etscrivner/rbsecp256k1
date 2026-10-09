# frozen_string_literal: true

require 'securerandom'

module Secp256k1
  # Wrapper around a secp256k1_context object.
  class Context
    # Create a new randomized context.
    #
    # @return [Secp256k1::Context] randomized context
    def self.create
      new(context_randomization_bytes: SecureRandom.random_bytes(32))
    end

    # Create a new non-randomized context.
    #
    # @return [Secp256k1::Context] non-randomized context
    def self.create_unrandomized
      new
    end

    # Generates a new random key pair.
    #
    # @return [Secp256k1::KeyPair] public-private key pair.
    def generate_key_pair
      key_pair_from_private_key(SecureRandom.random_bytes(32))
    end

    # Sign message bytes directly with fresh 32-byte auxiliary randomness.
    # No implicit hashing, padding, or truncation is performed.
    #
    # @param keypair [Secp256k1::KeyPair] key pair used for signing
    # @param message [String] message of any byte length, including zero
    #
    # @return [Secp256k1::SchnorrSignature] schnorr signature
    def sign_schnorr(keypair, message)
      sign_schnorr_custom(keypair, message, SecureRandom.random_bytes(32))
    end
  end
end
