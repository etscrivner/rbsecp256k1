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

    describe 'Schnorr signing edge cases' do
      let(:key_pair) { context.key_pair_from_private_key([('00' * 31) + '03'].pack('H*')) }
      let(:public_key) { key_pair.xonly_public_key }
      let(:auxrand) { "\x00" * 32 }

      %i[sign_schnorr sign_schnorr_custom].each do |method|
        context "using #{method}" do
          let(:sign_message) do
            lambda do |message|
              arguments = [key_pair, message]
              arguments << auxrand if method == :sign_schnorr_custom
              context.public_send(method, *arguments)
            end
          end

          it 'includes bytes after an embedded null byte' do
            message = "prefix\x00suffix".b
            signature = sign_message.call(message)

            expect(signature.verify(message, public_key)).to be true
            expect(signature.verify('prefix', public_key)).to be false
            expect(signature.verify("prefix\x00changed".b, public_key)).to be false
          end

          it 'signs multibyte strings using their bytes rather than character count' do
            # Sixteen UTF-8 characters occupy 32 bytes.
            message = "\u00e9" * 16
            signature = sign_message.call(message)

            expect(message.length).to eq(16)
            expect(message.bytesize).to eq(32)
            expect(signature.verify(message.b, public_key)).to be true
            expect(signature.verify(message.b.byteslice(0, message.length), public_key)).to be false
          end

          [nil, 123, []].each do |message|
            it "rejects a #{message.class} message" do
              expect { sign_message.call(message) }.to raise_error(TypeError)
            end
          end
        end
      end

      describe 'auxiliary randomness' do
        [0, 1, 17, 32, 100].each do |length|
          it "treats nil as zero randomness for a #{length}-byte message" do
            message = 'a' * length
            signature = context.sign_schnorr_custom(key_pair, message, nil)
            zero_signature = context.sign_schnorr_custom(key_pair, message, auxrand)

            expect(signature).to eq(zero_signature)
            expect(signature.verify(message, public_key)).to be true
          end
        end

        [0, 31, 33].each do |length|
          it "rejects #{length} bytes of auxiliary randomness" do
            expect { context.sign_schnorr_custom(key_pair, 'message', 'a' * length) }
              .to raise_error(Secp256k1::Error, 'schnorr signing auxrand must be 32-bytes in length')
          end
        end

        [false, 123, []].each do |randomness|
          it "rejects #{randomness.class} auxiliary randomness" do
            expect { context.sign_schnorr_custom(key_pair, 'message', randomness) }.to raise_error(TypeError)
          end
        end

        it 'accepts exactly 32 bytes of multibyte auxiliary randomness' do
          randomness = "\u00e9" * 16
          signature = context.sign_schnorr_custom(key_pair, 'message', randomness)

          expect(signature).to eq(context.sign_schnorr_custom(key_pair, 'message', randomness.b))
          expect(signature.verify('message', public_key)).to be true
        end
      end

      describe 'verification rejects altered inputs' do
        let(:message) { 'message'.b }
        let(:signature) { context.sign_schnorr_custom(key_pair, message, auxrand) }

        it 'rejects a changed message' do
          expect(signature.verify('changed', public_key)).to be false
        end

        it 'rejects a changed signature' do
          changed = signature.serialized.dup
          changed.setbyte(63, changed.getbyte(63) ^ 1)
          altered_signature = Secp256k1::SchnorrSignature.from_data(changed)

          expect(altered_signature.verify(message, public_key)).to be false
        end

        it 'rejects a different public key' do
          other_key = context.key_pair_from_private_key([('00' * 31) + '04'].pack('H*'))

          expect(signature.verify(message, other_key.xonly_public_key)).to be false
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
