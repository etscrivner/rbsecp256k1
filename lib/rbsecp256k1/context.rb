require 'securerandom'

module Secp256k1
  # Wrapper around a secp256k1_context object.
  class Context
    # Generates a new random key pair.
    #
    # @return [Secp256k1::KeyPair] public-private key pair.
    def generate_key_pair
      key_pair_from_private_key(SecureRandom.random_bytes(32))
    end
  end
end
