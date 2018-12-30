require 'spec_helper'

RSpec.describe Secp256k1::Signature do
  let(:context) { Secp256k1::Context.new }
  let(:message) { 'this is a test' }
  let(:key_pair) { context.generate_key_pair }
  let(:signature) { context.sign(key_pair.private_key, message) }

  describe '#der_encoded' do
    it 'returns a valid DER encoded signature' do
      der_encoded = signature.der_encoded

      expect(der_encoded).to be_a(String)
      expect(context.signature_from_der_encoded(der_encoded)).to eq(signature)
    end
  end

  describe '#compact' do
    it 'returns a valid compact signature' do
      compact = signature.compact

      expect(compact).to be_a(String)
      expect(compact.length).to eq(64)
      expect(context.signature_from_compact(compact)).to eq(signature)
    end
  end
end
