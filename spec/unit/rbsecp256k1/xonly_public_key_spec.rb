# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::XOnlyPublicKey do
  let(:context) { Secp256k1::Context.create }
  let(:key_pair) { context.generate_key_pair }
  let(:xonly_pubkey) { key_pair.xonly_public_key }

  describe '#serialized' do
    it 'returns a 32-byte string value' do
      serialized = xonly_pubkey.serialized
      expect(serialized).to be_a(String)
      expect(serialized.length).to eq(32)
    end
  end

  describe '.from_data' do
    it 'produces x-only public key from serialized form' do
      result = Secp256k1::XOnlyPublicKey.from_data(xonly_pubkey.serialized)
      expect(result).to eq(xonly_pubkey)
    end
  end

  describe '==' do
    it 'is false if keys do not match' do
      other = context.generate_key_pair.xonly_public_key
      expect(other).not_to eq(xonly_pubkey)
    end
  end
end
