# frozen_string_literal: true

require 'spec_helper'
require 'csv'

if Secp256k1.have_schnorr?
  RSpec.describe Secp256k1::SchnorrSignature do
    let(:context) { Secp256k1::Context.create }
    # These are from the BIP-340 test vectors
    let(:example_sig_data1) { Secp256k1::Util.hex_to_bin("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0") }
    let(:example_sig_data2) { Secp256k1::Util.hex_to_bin("6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A") }

    vectors = CSV.read(File.expand_path('../../fixtures/bip340-test-vectors.csv', __dir__), headers: true)
    # Cover 32-byte compatibility and BIP-340 messages of 0, 1, 17, and 100 bytes.
    vectors.select { |vector| %w[0 15 16 17 18].include?(vector['index']) }.each do |vector|
      # Empty CSV message fields represent a zero-byte message.
      message = [vector['message'].to_s].pack('H*')

      context "with official vector #{vector['index']} (#{message.bytesize} message bytes)" do
        let(:key_pair) { context.key_pair_from_private_key([vector['secret key']].pack('H*')) }
        let(:public_key) { Secp256k1::XOnlyPublicKey.from_data([vector['public key']].pack('H*')) }
        let(:auxrand) { [vector['aux_rand']].pack('H*') }
        let(:expected_signature) { Secp256k1::SchnorrSignature.from_data([vector['signature']].pack('H*')) }

        it 'verifies the official signature' do
          expect(expected_signature.verify(message, public_key)).to be true
        end

        it 'produces the exact official signature with supplied randomness' do
          expect(context.sign_schnorr_custom(key_pair, message, auxrand)).to eq(expected_signature)
        end

        it 'signs and verifies with generated randomness' do
          signature = context.sign_schnorr(key_pair, message)
          expect(signature.verify(message, public_key)).to be true
        end
      end
    end

    describe '.from_data' do
      it 'correctly loads signature from data' do
        sig = Secp256k1::SchnorrSignature.from_data(example_sig_data1)

        expect(sig.serialized).to eq(example_sig_data1)
      end
    end

    describe '==' do
      it 'does not match unequal values' do
        sig1 = Secp256k1::SchnorrSignature.from_data(example_sig_data1)
        sig2 = Secp256k1::SchnorrSignature.from_data(example_sig_data2)

        expect(sig1).not_to eq(sig2)
      end
    end

    describe 'Context#sign_schnorr' do
      it 'generates the expected signature using BIP-340 test vector' do
        secret_key = Secp256k1::Util.hex_to_bin('0000000000000000000000000000000000000000000000000000000000000003')
        message = Secp256k1::Util.hex_to_bin('0000000000000000000000000000000000000000000000000000000000000000')
        auxrand = Secp256k1::Util.hex_to_bin('0000000000000000000000000000000000000000000000000000000000000000')

        expected_signature = Secp256k1::SchnorrSignature.from_data(Secp256k1::Util.hex_to_bin('E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0'))
        expected_public_key = Secp256k1::XOnlyPublicKey.from_data(Secp256k1::Util.hex_to_bin('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'))

        key_pair = context.key_pair_from_private_key(secret_key)
        expect(key_pair.xonly_public_key).to eq(expected_public_key)

        expect(expected_signature.verify(message, key_pair.xonly_public_key)).to be true

        expect(context.sign_schnorr_custom(key_pair, message, auxrand)).to eq(expected_signature)

        # Just test that we can invoke this
        context.sign_schnorr(key_pair, message)
      end
    end
  end
end
