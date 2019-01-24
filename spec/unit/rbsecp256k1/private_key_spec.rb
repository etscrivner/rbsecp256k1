# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::PrivateKey do
  let(:context) { Secp256k1::Context.create }
  let(:key_pair) { context.generate_key_pair }

  it 'does not allow you to write data' do
    key_pair = context.generate_key_pair
    expect do
      key_pair.private_key.data = 'test'
    end.to raise_error(NoMethodError)
  end

  describe '.from_data' do
    it 'correctly loads private key from data' do
      data = Random.new.bytes(32)
      private_key = Secp256k1::PrivateKey.from_data(data)

      expect(private_key).to be_a(Secp256k1::PrivateKey)
      expect(private_key.data.bytes).to eq(data.bytes)
    end

    it 'loads a private key from data' do
      private_key = Secp256k1::PrivateKey.from_data(key_pair.private_key.data)

      expect(private_key).to be_a(Secp256k1::PrivateKey)
      expect(private_key.data.length).to eq(32)
      expect(private_key).to eq(key_pair.private_key)
    end

    it 'raises an error if private key has wrong length' do
      expect do
        Secp256k1::PrivateKey.from_data('test')
      end.to raise_error(Secp256k1::Error, 'private key data must be 32 bytes in length')
    end

    it 'raises an error if private key data is not string' do
      expect do
        Secp256k1::PrivateKey.from_data(1234)
      end.to raise_error(TypeError)
    end
  end
end
