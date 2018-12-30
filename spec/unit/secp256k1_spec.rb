require 'spec_helper'

RSpec.describe Secp256k1 do
  # Pull down the WITH_RECOVERY environment variable. This should be '1' in
  # environments where tests are being run with the recovery module installed.
  let(:with_recovery) { ENV.fetch('WITH_RECOVERY', '0') == '1' }

  describe '.have_recovery?' do
    it 'has the expected recovery module' do
      expect(Secp256k1.have_recovery?).to eq(with_recovery)
    end
  end

  describe '.have_ecdh?' do
    it 'has the expected ecdh module' do
      expect(Secp256k1.have_ecdh?).to be false
    end
  end
end
