require 'spec_helper'

RSpec.describe Secp256k1::PublicKey do
  let(:context) { Secp256k1::Context.new }
  let(:key_pair) { context.generate_key_pair }

  describe '#initialize' do
    it 'initializes a public key from private key data' do
      public_key = Secp256k1::PublicKey.new(context, key_pair.private_key)

      expect(public_key).to be_a(Secp256k1::PublicKey)
    end

    it 'raises an error if the private key data is invalid' do
      expect do
        Secp256k1::PublicKey.new(context, 'test')
      end.to raise_error(TypeError)
    end
  end

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
