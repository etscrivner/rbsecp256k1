require 'spec_helper'

RSpec.describe Secp256k1::PrivateKey do
  let(:context) { Secp256k1::Context.new }

  it 'does not allow you to write data' do
    key_pair = context.generate_key_pair
    expect do
      key_pair.private_key.data = 'test'
    end.to raise_error(NoMethodError)
  end
end
