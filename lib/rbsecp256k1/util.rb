module Secp256k1
  module Util
    # Converts a binary string to a hex string.
    #
    # @param binary_string [String] binary string to be converted.
    # @return [String] hex string equivalent of the given binary string.
    def self.bin_to_hex(binary_string)
      binary_string.unpack('H*').first
    end

    # Converts a hex string to a binary string.
    #
    # @param hex_string [String] string with hexadeimcal value.
    # @return [String] binary string equivalent of the given hex string.
    def self.hex_to_bin(hex_string)
      [hex_string].pack('H*')
    end
  end
end
