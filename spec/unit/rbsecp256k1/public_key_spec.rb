require 'spec_helper'

RSpec.describe Secp256k1::PublicKey do
  let(:context) { Secp256k1::Context.new }
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
end
