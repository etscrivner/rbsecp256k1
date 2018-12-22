require 'rbsecp256k1'

RSpec.describe Secp256k1 do
  let(:context) { Secp256k1::Context.new }
  let(:key_pair) { context.generate_key_pair }
  let(:text_message) { 'This is some text' }
  let(:binary_data) { "yuyY\xC8\v\x9E\xBEu\xB9\x02\xEA\xA5\x82V\xAC\xAA9\xA0\xA4U\"z\x99,J\x90\xADk8\xB2\xE1" }
  let(:private_key_data) { "I\nX\x85\xAEz}\n\x9B\xA4\\\x81)\xD4\x9Aq\xFDH\t\xBE\x8EP\xC5.\xC6\x1F7-\x86\xA0\xCB\xF9" }
  let(:expected_private_key_hex) { '490a5885ae7a7d0a9ba45c8129d49a71fd4809be8e50c52ec61f372d86a0cbf9' }
  let(:expected_compressed_pubkey_hex) { '0224a2e7bb31c47c744ee6e44a2ded9a5baf662d3c14845e51512214c391e4f2b5' }
  let(:der_encoded_sig) { "0D\x02 <\xC6\x7F/\x921l\x89Z\xFBs\x89p\xEE\x18u\x8B\x92\x9D\xA6\x84\xC5Y<t\xB7\xF1\f\xEE\f\x81J\x02 \t\"\xDF]\x1D\xA7W@^\xAAokH\b\x00\xE2L\xCF\x82\xA3\x05\x1E\x00\xF9\xFC\xB19\x0F\x93|\xB1f" }

  describe 'key pairs' do
    it 'can generate a new key pair' do
      key_pair = context.generate_key_pair

      expect(key_pair).to be_a(Secp256k1::KeyPair)
      expect(key_pair.public_key).to be_a(Secp256k1::PublicKey)
      expect(key_pair.private_key).to be_a(Secp256k1::PrivateKey)
    end

    it 'generated keys are different' do
      key_pair1 = context.generate_key_pair
      key_pair2 = context.generate_key_pair

      expect(key_pair1.private_key.data.bytes).not_to eq(key_pair2.private_key.data.bytes)
    end

    it 'can load key pair from private key' do
      key_pair = context.key_pair_from_private_key(private_key_data)

      expect(key_pair).to be_a(Secp256k1::KeyPair)
      expect(Secp256k1::Util.bin_to_hex(key_pair.private_key.data))
        .to eq(expected_private_key_hex)
      expect(Secp256k1::Util.bin_to_hex(key_pair.public_key.as_compressed))
        .to eq(expected_compressed_pubkey_hex)
    end

    it 'can load public key from uncompressed key' do
      public_key_uncompressed = context.public_key_from_data(
        key_pair.public_key.as_uncompressed
      )

      expect(public_key_uncompressed.as_uncompressed.bytes)
        .to eq(key_pair.public_key.as_uncompressed.bytes)
    end

    it 'can load public key from compressed key' do
      public_key_compressed = context.public_key_from_data(
        key_pair.public_key.as_uncompressed
      )

      expect(public_key_compressed.as_compressed.bytes)
        .to eq(key_pair.public_key.as_compressed.bytes)
    end

    describe 'PublicKey' do
      it 'can produce uncompressed key' do
        uncompressed_key = key_pair.public_key.as_uncompressed

        expect(uncompressed_key).to be_a(String)
        expect(uncompressed_key.length).to eq(65)
      end

      it 'can produce compressed key' do
        compressed_key = key_pair.public_key.as_compressed

        expect(compressed_key).to be_a(String)
        expect(compressed_key.length).to eq(33)
      end
    end
  end

  describe 'signatures and signing' do
    it 'can sign a text message' do
      signature = context.sign(key_pair.private_key, text_message)

      expect(signature).to be_a(Secp256k1::Signature)
    end

    it 'can sign binary data' do
      signature = context.sign(key_pair.private_key, binary_data)

      expect(signature).to be_a(Secp256k1::Signature)
    end

    it 'contains the DER encoded signature data' do
      signature = context.sign(key_pair.private_key, binary_data)

      expect(signature.der_encoded).to be_a(String)
    end

    it 'can load a DER encoded signature from binary data' do
      # Uses a hand-built key pair and signature to test loading a verification
      signature = context.signature_from_der_encoded(der_encoded_sig)
      key_pair = context.key_pair_from_private_key("yuyY\xC8\v\x9E\xBEu\xB9\x02\xEA\xA5\x82V\xAC\xAA9\xA0\xA4U\"z\x99,J\x90\xADk8\xB2\xE1")

      expect(signature).to be_a(Secp256k1::Signature)
      expect(context.verify(signature, key_pair.public_key, "test message"))
        .to be true
    end
  end

  describe 'verification' do
    it 'produces valid signatures on text messages' do
      signature = context.sign(key_pair.private_key, text_message)

      expect(signature).to be_a(Secp256k1::Signature)
      expect(context.verify(signature, key_pair.public_key, text_message)).to be true
    end

    it 'produces valid signatures on binary data' do
      signature = context.sign(key_pair.private_key, binary_data)

      expect(signature).to be_a(Secp256k1::Signature)
      expect(context.verify(signature, key_pair.public_key, binary_data)).to be true
    end

    it 'fails to verify signatures when data does not match' do
      signature = context.sign(key_pair.private_key, binary_data)

      expect(signature).to be_a(Secp256k1::Signature)
      expect(context.verify(signature, key_pair.public_key, text_message)).to be false
    end
  end
end
