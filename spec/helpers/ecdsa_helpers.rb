# frozen_string_literal: true

require 'digest'

module ECDSAHelpers
  # Computes the SHA-256 hash of the given data.
  #
  # @param data [String] binary or text data to be hashed.
  # @return [String] 32-byte SHA-256 hash as binary string.
  def sha256(data)
    Digest::SHA256.digest(data)
  end
end
