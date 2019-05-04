# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::Util do
  describe '.bin_to_hex' do
    it 'returns the expected hex string' do
      expect(Secp256k1::Util.bin_to_hex("\xDE\xAD\xBE\xEF")).to eq("deadbeef")
    end
  end

  describe '.hex_to_bin' do
    it 'returns the expected binary string' do
      expect(Secp256k1::Util.hex_to_bin('DEADBEEF').bytes)
        .to eq("\xDE\xAD\xBE\xEF".bytes)
    end

    it 'raises an error if string is not valid hex' do
      expect do
        Secp256k1::Util.hex_to_bin("test")
      end.to raise_error(ArgumentError, "Invalid hexadecimal string")
    end
  end
end
