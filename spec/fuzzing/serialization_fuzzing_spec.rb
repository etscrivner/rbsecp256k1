# frozen_string_literal: true

require 'spec_helper'
require_relative '../helpers/serialization_fuzzing_helpers'

# Replay failures with: bundle exec rspec spec/fuzzing/serialization_fuzzing_spec.rb --seed SEED
# This is seeded parser stress testing, not coverage-guided fuzzing.
RSpec.describe 'Fuzzing deserialization methods' do
  include SerializationFuzzingHelpers

  let(:context) { Secp256k1::Context.create }
  let(:seed) { RSpec.configuration.seed }
  let(:random) { Random.new(seed) }
  let(:private_key_data) { 'a'.b * 32 }
  let(:key_pair) { context.key_pair_from_private_key(private_key_data) }
  let(:digest) { 'b'.b * 32 }
  let(:signature) { context.sign(key_pair.private_key, digest) }

  let(:boundary_inputs) do
    [0, 1, 31, 32, 33, 63, 64, 65, 71, 72, 73, 1000].flat_map do |length|
      ["\x00".b * length, "\xff".b * length, random.bytes(length)]
    end
  end

  def fuzz_parser(valid_inputs, malformed_inputs: [], &parser)
    # Valid corpus entries must succeed, not disappear into expected rejections.
    valid_inputs.each(&parser)
    result = fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000, corpus: valid_inputs + malformed_inputs + boundary_inputs, &parser)
    expect_completed_fuzz_run(result, valid_inputs.length)
  end

  def expect_completed_fuzz_run(result, valid_count)
    expect(result[:attempted]).to eq(10_000)
    expect(result.values_at(:accepted, :rejected).sum).to eq(10_000)
    expect(result[:accepted]).to be >= valid_count
    expect(result[:rejected]).to be_positive
  end

  it 'exercises Context.new with valid and invalid randomization lengths' do
    fuzz_parser([private_key_data]) do |data|
      Secp256k1::Context.new(context_randomization_bytes: data)
    end
  end

  it 'exercises Context#key_pair_from_private_key' do
    fuzz_parser([private_key_data]) do |data|
      expect(context.key_pair_from_private_key(data).public_key.compressed.bytesize).to eq(33)
    end
  end

  it 'exercises PrivateKey.from_data' do
    fuzz_parser([private_key_data]) do |data|
      expect(Secp256k1::PrivateKey.from_data(data).data).to eq(data)
    end
  end

  it 'exercises PublicKey.from_data for compressed and uncompressed points' do
    fuzz_parser([key_pair.public_key.compressed, key_pair.public_key.uncompressed]) do |data|
      expect(Secp256k1::PublicKey.from_data(data).compressed.bytesize).to eq(33)
    end
  end

  it 'exercises XOnlyPublicKey.from_data' do
    fuzz_parser([key_pair.xonly_public_key.serialized]) do |data|
      expect(Secp256k1::XOnlyPublicKey.from_data(data).serialized).to eq(data)
    end
  end

  it 'exercises Signature.from_der_encoded with valid and malformed DER' do
    der = signature.der_encoded
    malformed = [der.byteslice(0, der.bytesize - 1), der + "\x00".b,
                 der.dup.tap { |data| data.setbyte(0, 0x31) }, "\x30\x80\x00\x00".b]
    malformed.each do |data|
      expect { Secp256k1::Signature.from_der_encoded(data) }.to raise_error(Secp256k1::Error)
    end
    fuzz_parser([der], malformed_inputs: malformed) do |data|
      parsed = Secp256k1::Signature.from_der_encoded(data)
      expect(Secp256k1::Signature.from_der_encoded(parsed.der_encoded)).to eq(parsed)
    end
  end

  it 'exercises Signature.from_compact' do
    fuzz_parser([signature.compact]) do |data|
      expect(Secp256k1::Signature.from_compact(data).compact).to eq(data)
    end
  end

  it 'exercises recoverable compact signatures with recovery IDs 0 through 3' do
    skip 'recovery module not available' unless Secp256k1.have_recovery?

    compact, = context.sign_recoverable(key_pair.private_key, digest).compact
    (0..3).each do |recovery_id|
      expect(context.recoverable_signature_from_compact(compact, recovery_id).compact).to eq([compact, recovery_id])
    end
    fuzz_parser([compact]) do |data|
      recovery_id = random.rand(0..3)
      expect(context.recoverable_signature_from_compact(data, recovery_id).compact).to eq([data, recovery_id])
    end
  end

  it 'rejects out-of-range recovery IDs with a valid-length compact signature' do
    skip 'recovery module not available' unless Secp256k1.have_recovery?

    compact, = context.sign_recoverable(key_pair.private_key, digest).compact
    [-1, 4].each do |recovery_id|
      expect do
        context.recoverable_signature_from_compact(compact, recovery_id)
      end.to raise_error(Secp256k1::Error, 'invalid recovery ID, must be in range [0, 3]')
    end
  end

  it 'exercises SchnorrSignature.from_data and verification' do
    skip 'Schnorr module not available' unless Secp256k1.have_schnorr?

    signed = context.sign_schnorr_custom(key_pair, 'message', nil)
    expect(signed.verify('message', key_pair.xonly_public_key)).to be true
    fuzz_parser([signed.serialized]) do |data|
      parsed = Secp256k1::SchnorrSignature.from_data(data)
      expect(parsed.serialized).to eq(data)
      expect([true, false]).to include(parsed.verify('message', key_pair.xonly_public_key))
    end
  end
end
