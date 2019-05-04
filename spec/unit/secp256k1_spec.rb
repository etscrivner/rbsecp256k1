# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1 do
  # Pull down the WITH_RECOVERY environment variable. This should be '0' in
  # environments where tests are being run with the recovery module
  # uninstalled. The recovery module will be installed by default.
  let(:with_recovery) { ENV.fetch('WITH_RECOVERY', '1') == '1' }

  # Pull down the WITH_ECDH environment variable. This should be '0' in
  # environments where tests are being run with the ECDH module not installed.
  # The ECDH module will be installed by default.
  let(:with_ecdh) { ENV.fetch('WITH_ECDH', '1') == '1' }

  describe '.have_recovery?' do
    it 'has the expected recovery module' do
      expect(Secp256k1.have_recovery?).to eq(with_recovery)
    end
  end

  describe '.have_ecdh?' do
    it 'has the expected ecdh module' do
      expect(Secp256k1.have_ecdh?).to eq(with_ecdh)
    end
  end
end
