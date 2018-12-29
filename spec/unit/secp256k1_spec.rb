require 'spec_helper'

RSpec.describe Secp256k1 do
  describe '.have_recovery?' do
    it 'is true when built with recovery module' do
      expect(Secp256k1).to be_have_recovery
    end
  end
end
