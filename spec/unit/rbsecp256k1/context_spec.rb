require 'spec_helper'

RSpec.describe Secp256k1::Context do
  subject { Secp256k1::Context.new }
  let(:key_pair) { subject.generate_key_pair }
  let(:message) { 'test message' }

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

      expect(key_pair1.private_key.data.bytes)
        .not_to eq(key_pair2.private_key.data.bytes)
      expect(key_pair1.public_key.compressed.bytes)
        .not_to eq(key_pair2.public_key.compressed.bytes)
    end
  end

  describe '#key_pair_from_private_key' do
    let(:private_key_data) { "I\nX\x85\xAEz}\n\x9B\xA4\\\x81)\xD4\x9Aq\xFDH\t\xBE\x8EP\xC5.\xC6\x1F7-\x86\xA0\xCB\xF9" }
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
      end.to raise_error(ArgumentError, 'private key data must be 32 bytes in length')
    end
  end

  describe '#public_key_from_data' do
    it 'correctly loads a compressed public key' do
      public_key = subject.public_key_from_data(key_pair.public_key.compressed)

      expect(public_key.compressed.bytes)
        .to eq(key_pair.public_key.compressed.bytes)
    end

    it 'correctly loads an uncompressed public key' do
      public_key = subject.public_key_from_data(
        key_pair.public_key.uncompressed
      )

      expect(public_key.uncompressed.bytes)
        .to eq(key_pair.public_key.uncompressed.bytes)
    end

    it 'raises an error if public key is invalid' do
      # TODO: If this test is ever flakey replace randomness with static bad key data
      expect do
        subject.public_key_from_data(Random.new.bytes(64))
      end.to raise_error(RuntimeError, 'invalid public key data')
    end
  end

  describe '#sign' do
    let(:text_message) { 'This is some text' }
    let(:binary_data) { "yuyY\xC8\v\x9E\xBEu\xB9\x02\xEA\xA5\x82V\xAC\xAA9\xA0\xA4U\"z\x99,J\x90\xADk8\xB2\xE1" }

    it 'can sign text data' do
      signature = subject.sign(key_pair.private_key, text_message)

      expect(signature).to be_a(Secp256k1::Signature)
    end

    it 'can sign binary data' do
      signature = subject.sign(key_pair.private_key, binary_data)

      expect(signature).to be_a(Secp256k1::Signature)
    end

    it 'raises an error if private key not given' do
      expect do
        subject.sign(subject, text_message)
      end.to raise_error(TypeError)
    end
  end

  describe '#signature_from_compact' do
    it 'can load a compact signature' do
      signature = subject.sign(key_pair.private_key, message)
      result = subject.signature_from_compact(signature.compact)

      expect(result).to be_a(Secp256k1::Signature)
    end

    it 'raises an error if invalid signature data type is given' do
      expect do
        subject.signature_from_compact(123)
      end.to raise_error(TypeError)
    end
  end

  describe '#signature_from_der_encoded' do
    it 'can load a der encoded signature' do
      signature = subject.sign(key_pair.private_key, message)
      result = subject.signature_from_compact(signature.der_encoded)

      expect(result).to be_a(Secp256k1::Signature)
    end

    it 'raises an error if invalid signature data is given' do
      expect do
        subject.signature_from_compact(123)
      end.to raise_error(TypeError)
    end
  end

  describe '#verify' do
    it 'verifies signatures with matching public key and data' do
      signature = subject.sign(key_pair.private_key, message)

      expect(subject.verify(signature, key_pair.public_key, message)).to be true
    end

    it 'is false when public key does not match' do
      signature = subject.sign(key_pair.private_key, message)
      bad_key_pair = subject.generate_key_pair

      expect(subject.verify(signature, bad_key_pair.public_key, message))
        .to be false
    end

    it 'is false when data does not match' do
      signature = subject.sign(key_pair.private_key, message)
      bad_message = 'bad message'

      expect(subject.verify(signature, key_pair.public_key, bad_message))
        .to be false
    end
  end
end