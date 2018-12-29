require 'spec_helper'

RSpec.describe Secp256k1::PrivateKey do
  let(:context) { Secp256k1::Context.new }

  it 'does not allow you to write data' do
    private_key = Secp256k1::PrivateKey.generate(context)
    expect do
      private_key.data = 'test'
    end.to raise_error(NoMethodError)
  end

  describe '.generate' do
    it 'generates a new private key' do
      private_key = Secp256k1::PrivateKey.generate(context)
      expect(private_key).to be_a(Secp256k1::PrivateKey)
      expect(private_key.data).to be_a(String)
      expect(private_key.data.length).to eq 32
    end
  end
end
