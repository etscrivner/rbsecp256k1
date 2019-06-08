# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1::Context do
  subject { Secp256k1::Context.create }
  let(:key_pair) { subject.generate_key_pair }
  let(:message) { 'test message' }
  let(:private_key_data) { "I\nX\x85\xAEz}\n\x9B\xA4\\\x81)\xD4\x9Aq\xFDH\t\xBE\x8EP\xC5.\xC6\x1F7-\x86\xA0\xCB\xF9" }

  describe '#initialize' do
    it 'raises an error if too few bytes are given' do
      expect do
        Secp256k1::Context.new(context_randomization_bytes: '1234')
      end.to raise_error(Secp256k1::Error, "context_randomization_bytes must be 32 bytes in length")
    end

    it 'raises an error if too many bytes are given' do
      expect do
        Secp256k1::Context.new(context_randomization_bytes: '1' * 33)
      end.to raise_error(Secp256k1::Error, "context_randomization_bytes must be 32 bytes in length")
    end

    it 'allows for 32 bytes of randomness' do
      Secp256k1::Context.new(context_randomization_bytes: SecureRandom.random_bytes(32))
    end
  end

  describe '#generate_key_pair' do
    it 'generates a new key pair' do
      key_pair = subject.generate_key_pair

      expect(key_pair).to be_a(Secp256k1::KeyPair)
      expect(key_pair.public_key).to be_a(Secp256k1::PublicKey)
      expect(key_pair.private_key).to be_a(Secp256k1::PrivateKey)
    end

    it 'generates different keys on each call' do
      key_pair1 = subject.generate_key_pair
      key_pair2 = subject.generate_key_pair

      expect(key_pair1).not_to eq(key_pair2)
      expect(key_pair1).not_to eq(key_pair2)
    end
  end

  describe '#key_pair_from_private_key' do
    let(:expected_private_key_hex) { '490a5885ae7a7d0a9ba45c8129d49a71fd4809be8e50c52ec61f372d86a0cbf9' }
    let(:expected_compressed_pubkey_hex) { '0224a2e7bb31c47c744ee6e44a2ded9a5baf662d3c14845e51512214c391e4f2b5' }

    it 'returns key pair with private key corresponding to data' do
      key_pair = subject.key_pair_from_private_key(private_key_data)

      expect(Secp256k1::Util.bin_to_hex(key_pair.private_key.data))
        .to eq(expected_private_key_hex)
    end

    it 'returns key pair with public key corresponding to private key' do
      key_pair = subject.key_pair_from_private_key(private_key_data)

      expect(Secp256k1::Util.bin_to_hex(key_pair.public_key.compressed))
        .to eq(expected_compressed_pubkey_hex)
    end

    it 'raises an error if private key data is invalid' do
      expect do
        subject.key_pair_from_private_key('abcdefghijklmnopqrstuvwxyzabcd')
      end.to raise_error(Secp256k1::Error, 'private key data must be 32 bytes in length')
    end

    it 'raises an error if private key data is not string' do
      expect do
        subject.key_pair_from_private_key(1234)
      end.to raise_error(TypeError)
    end
  end

  describe '#sign' do
    let(:text_message) { 'This is some text' }
    let(:binary_data) { "yuyY\xC8\v\x9E\xBEu\xB9\x02\xEA\xA5\x82V\xAC\xAA9\xA0\xA4U\"z\x99,J\x90\xADk8\xB2\xE1" }

    it 'can sign text data' do
      signature = subject.sign(key_pair.private_key, sha256(text_message))

      expect(signature).to be_a(Secp256k1::Signature)
    end

    it 'can sign binary data' do
      signature = subject.sign(key_pair.private_key, sha256(binary_data))

      expect(signature).to be_a(Secp256k1::Signature)
    end

    it 'raises an error if private key not given' do
      expect do
        subject.sign(subject, sha256(text_message))
      end.to raise_error(TypeError)
    end

    it 'raises an error if signature is not 32 bytes' do
      expect do
        subject.sign(key_pair.private_key, text_message)
      end.to raise_error(Secp256k1::Error)
    end
  end

  describe '#verify' do
    it 'verifies signatures with matching public key and data' do
      signature = subject.sign(key_pair.private_key, sha256(message))

      expect(subject.verify(signature, key_pair.public_key, sha256(message))).to be true
    end

    it 'is false when public key does not match' do
      signature = subject.sign(key_pair.private_key, sha256(message))
      bad_key_pair = subject.generate_key_pair

      expect(subject.verify(signature, bad_key_pair.public_key, sha256(message)))
        .to be false
    end

    it 'is false when data does not match' do
      signature = subject.sign(key_pair.private_key, sha256(message))
      bad_message = 'bad message'

      expect(subject.verify(signature, key_pair.public_key, sha256(bad_message)))
        .to be false
    end

    it 'raises an error if hash is not 32 bytes' do
      signature = subject.sign(key_pair.private_key, sha256(message))
      bad_key_pair = subject.generate_key_pair

      expect do
        subject.verify(signature, bad_key_pair.public_key, message)
      end.to raise_error(Secp256k1::Error)
    end
  end

  if Secp256k1.have_recovery?
    describe '#sign_recoverable' do
      let(:text_message) { 'This is some text' }
      let(:binary_data) { "yuyY\xC8\v\x9E\xBEu\xB9\x02\xEA\xA5\x82V\xAC\xAA9\xA0\xA4U\"z\x99,J\x90\xADk8\xB2\xE1" }

      it 'can sign text data' do
        signature = subject.sign_recoverable(key_pair.private_key, sha256(text_message))

        expect(signature).to be_a(Secp256k1::RecoverableSignature)
      end

      it 'can sign binary data' do
        signature = subject.sign_recoverable(key_pair.private_key, sha256(binary_data))

        expect(signature).to be_a(Secp256k1::RecoverableSignature)
      end

      it 'raises an error if private key not given' do
        expect do
          subject.sign_recoverable(subject, sha256(text_message))
        end.to raise_error(TypeError)
      end

      it 'raises an error if hash is the wrong length' do
        expect do
          subject.sign_recoverable(subject, text_message)
        end.to raise_error(Secp256k1::Error)
      end
    end

    describe '#recoverable_signature_from_compact' do
      it 'recovers signature from data' do
        signature = subject.sign_recoverable(key_pair.private_key, sha256('test'))
        compact, recovery_id = signature.compact

        recovered_signature = subject.recoverable_signature_from_compact(
          compact, recovery_id
        )

        expect(recovered_signature).to be_a(Secp256k1::RecoverableSignature)
        expect(recovered_signature).to eq(signature)
      end

      it 'raises an error if compact signature is not the right size' do
        expect do
          subject.recoverable_signature_from_compact('test', 1)
        end.to raise_error(Secp256k1::Error, 'compact signature is not 64 bytes')
      end

      it 'raises an error if compact signature data is not string' do
        expect do
          subject.recoverable_signature_from_compact(1234, 1)
        end.to raise_error(TypeError)
      end

      it 'raises an error if recovery id is less < 0' do
        signature = subject.sign_recoverable(key_pair.private_key, sha256('test'))
        compact, = signature.compact

        expect do
          subject.recoverable_signature_from_compact(compact, -1)
        end.to raise_error(Secp256k1::Error, /invalid recovery ID/)
      end

      it 'raises an error if recovery id is > 3' do
        signature = subject.sign_recoverable(key_pair.private_key, sha256('test'))
        compact, = signature.compact

        expect do
          subject.recoverable_signature_from_compact(compact, 4)
        end.to raise_error(Secp256k1::Error, /invalid recovery ID/)
      end
    end
  end

  if Secp256k1.have_ecdh?
    describe '#ecdh' do
      it 'produces a shared secret from keys' do
        shared_secret = subject.ecdh(key_pair.public_key, key_pair.private_key)

        expect(shared_secret).to be_a(Secp256k1::SharedSecret)
        expect(shared_secret.data).to be_a(String)
        expect(shared_secret.data.length).to eq(32)
      end
    end
  end
end
