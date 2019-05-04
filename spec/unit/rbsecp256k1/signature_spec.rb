# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::Signature do
  let(:context) { Secp256k1::Context.create }
  let(:message) { 'this is a test' }
  let(:key_pair) { context.generate_key_pair }
  let(:signature) { context.sign(key_pair.private_key, sha256(message)) }

  describe '.from_compact' do
    it 'can load a compact signature' do
      signature = context.sign(key_pair.private_key, sha256(message))
      result = Secp256k1::Signature.from_compact(signature.compact)

      expect(result).to be_a(Secp256k1::Signature)
      expect(result).to eq(signature)
    end

    it 'raises an error if invalid signature data type is given' do
      expect do
        Secp256k1::Signature.from_compact(123)
      end.to raise_error(TypeError)
    end
  end

  describe '.from_der_encoded' do
    it 'can load a der encoded signature' do
      signature = context.sign(key_pair.private_key, sha256(message))
      result = Secp256k1::Signature.from_der_encoded(signature.der_encoded)

      expect(result).to be_a(Secp256k1::Signature)
      expect(result).to eq(signature)
    end

    it 'raises an error if signature data is not string' do
      expect do
        Secp256k1::Signature.from_der_encoded(123)
      end.to raise_error(TypeError)
    end
  end

  describe '#der_encoded' do
    it 'returns a valid DER encoded signature' do
      der_encoded = signature.der_encoded

      expect(der_encoded).to be_a(String)
      expect(Secp256k1::Signature.from_der_encoded(der_encoded)).to eq(signature)
    end
  end

  describe '#compact' do
    it 'returns a valid compact signature' do
      compact = signature.compact

      expect(compact).to be_a(String)
      expect(compact.length).to eq(64)
      expect(Secp256k1::Signature.from_compact(compact)).to eq(signature)
    end
  end

  describe '#normalized' do
    # Data taken from https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/lib.rs
    # Original note:
    # nb this is a transaction on testnet
    # txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
    #      input number 3
    let(:unnormalized_der_sig) do
      '3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45'
    end
    let(:public_key_data) do
      '031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43'
    end
    let(:message_hash) do
      'a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d'
    end

    it 'returns the normalized form of the signature' do
      was_normalized, normalized = signature.normalized

      expect(normalized).to be_a(Secp256k1::Signature)
      expect(was_normalized).to be false
      expect(normalized).to eq(signature)
    end

    it 'computes normalized form of signature' do
      signature = Secp256k1::Signature.from_der_encoded(
        Secp256k1::Util.hex_to_bin(unnormalized_der_sig)
      )

      was_normalized, normalized = signature.normalized
      expect(was_normalized).to be true
      expect(normalized).not_to eq(signature)
    end
  end
end
