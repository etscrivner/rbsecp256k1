# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::PublicKey do
  let(:context) { Secp256k1::Context.create }
  let(:key_pair) { context.generate_key_pair }

  describe '#uncompressed' do
    it 'returns the uncompressed form of the public key' do
      uncompressed = key_pair.public_key.uncompressed
      expect(uncompressed).to be_a(String)
      expect(uncompressed.length).to eq(65)
    end
  end

  describe '#compressed' do
    it 'returns the compressed form of the public key' do
      compressed = key_pair.public_key.compressed
      expect(compressed).to be_a(String)
      expect(compressed.length).to eq(33)
    end
  end

  describe '.from_data' do
    it 'loads compressed public key' do
      public_key = Secp256k1::PublicKey.from_data(key_pair.public_key.compressed)
      expect(public_key).to eq(key_pair.public_key)
    end

    it 'loads uncompressed public key' do
      public_key = Secp256k1::PublicKey.from_data(key_pair.public_key.uncompressed)
      expect(public_key).to eq(key_pair.public_key)
    end

    it 'raises an error if public key is invalid' do
      expect do
        Secp256k1::PublicKey.from_data(Random.new.bytes(64))
      end.to raise_error(Secp256k1::DeserializationError, 'invalid public key data')
    end

    it 'raises an error if public key data is not string' do
      expect do
        Secp256k1::PublicKey.from_data(1234)
      end.to raise_error(TypeError)
    end
  end
end
