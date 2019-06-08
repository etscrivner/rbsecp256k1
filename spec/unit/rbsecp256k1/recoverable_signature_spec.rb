# frozen_string_literal: true

require 'spec_helper'

if Secp256k1.have_recovery?
  RSpec.describe Secp256k1::RecoverableSignature do
    let(:context) { Secp256k1::Context.create }
    let(:key_pair) { context.generate_key_pair }
    let(:text_message) { sha256('more test stuff') }

    describe '#compact' do
      it 'returns the compact signature and recovery id' do
        signature = context.sign_recoverable(key_pair.private_key, text_message)

        signature, recovery_id = signature.compact
        expect(signature).to be_a(String)
        expect(signature.length).to be(64)
        expect(recovery_id).to be_a(Integer)
      end
    end

    describe '#to_signature' do
      it 'returns the non-recoverable signature object' do
        recoverable_signature = context.sign_recoverable(
          key_pair.private_key, text_message
        )
        compact, = recoverable_signature.compact

        signature = recoverable_signature.to_signature
        expect(signature).to be_a(Secp256k1::Signature)
        expect(signature.compact.bytes).to eq(compact.bytes)
      end
    end

    describe '#recover_public_key' do
      it 'recovers the public key from signature' do
        recoverable_signature = context.sign_recoverable(
          key_pair.private_key, text_message
        )

        recovered_public_key = recoverable_signature.recover_public_key(
          text_message
        )

        expect(recovered_public_key).to be_a(Secp256k1::PublicKey)
        expect(recovered_public_key.compressed.bytes)
          .to eq(key_pair.public_key.compressed.bytes)
      end

      it 'bad data to result in wrong public key' do
        recoverable_signature = context.sign_recoverable(
          key_pair.private_key, text_message
        )

        public_key = recoverable_signature.recover_public_key(
          sha256('bad data')
        )

        expect(public_key).to be_a(Secp256k1::PublicKey)
        expect(public_key.compressed.bytes)
          .not_to eq(key_pair.public_key.compressed.bytes)
      end
    end
  end
end
