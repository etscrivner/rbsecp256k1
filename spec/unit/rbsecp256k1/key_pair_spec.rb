# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::KeyPair do
  let(:context) { Secp256k1::Context.create }
  let(:key_pair) { context.generate_key_pair }

  describe '#initialize' do
    it 'raises an error if public key is invalid' do
      expect do
        Secp256k1::KeyPair.new(key_pair.private_key, key_pair.private_key)
      end.to raise_error(TypeError, /wrong argument type PrivateKey/)
    end

    it 'raises an error if private key is invalid' do
      expect do
        Secp256k1::KeyPair.new(key_pair.public_key, key_pair.public_key)
      end.to raise_error(TypeError, /wrong argument type PublicKey/)
    end
  end
end
