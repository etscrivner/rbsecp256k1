require 'rbsecp256k1'

RSpec.describe Secp256k1 do
  let(:context) { Secp256k1::Context.new }
  let(:key_pair) { context.generate_key_pair }
  let(:text_message) { 'This is some text' }
  let(:binary_data) { "yuyY\xC8\v\x9E\xBEu\xB9\x02\xEA\xA5\x82V\xAC\xAA9\xA0\xA4U\"z\x99,J\x90\xADk8\xB2\xE1" }

  describe 'key pair generation' do
    it 'can generate a new key pair' do
      key_pair = context.generate_key_pair

      expect(key_pair).to be_a(Secp256k1::KeyPair)
      expect(key_pair.public_key).to be_a(Secp256k1::PublicKey)
      expect(key_pair.private_key).to be_a(Secp256k1::PrivateKey)
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
