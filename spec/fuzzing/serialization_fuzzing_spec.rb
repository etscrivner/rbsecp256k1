# frozen_string_literal: true

require 'spec_helper'

# Fuzzing tests check deserialization methods against randomly generated data.
# These tests reuse the random seed provided to RSpec so that failures are
# reproducible.

RSpec.describe 'Fuzzing deserialization methods' do
  let(:context) { Secp256k1::Context.create }
  let(:seed) { RSpec.configuration.seed }
  let(:random) { Random.new(seed) }

  before do
    srand(seed)
  end

  def random_binary_data(min_size, max_size)
    num_bytes = rand(min_size..max_size)
    random.bytes(num_bytes)
  end

  # rubocop:disable Lint/SuppressedException
  def fuzz_random_binary_data(iterations, min_bytes:, max_bytes:, &_block)
    iterations.times do
      yield random_binary_data(min_bytes, max_bytes)
    end
  rescue StandardError
    # Ignore errors, we're looking for crashes
  end
  # rubocop:enable Lint/SuppressedException

  it 'does not crash Context#initialize' do
    fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000) do |fuzzing_data|
      Context.new(context_randomization_bytes: fuzzing_data)
    end
  end

  it 'does not crash Context#key_pair_from_private_key' do
    fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000) do |fuzzing_data|
      context.key_pair_from_private_key(fuzzing_data)
    end
  end

  it 'does not crash Context#private_key_from_data' do
    fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000) do |fuzzing_data|
      context.private_key_from_data(fuzzing_data)
    end
  end

  it 'does not crash Context#recoverable_signature_from_compact' do
    if Secp256k1.have_recovery?
      fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000) do |fuzzing_data|
        context.recoverable_signature_from_compact(fuzzing_data, rand(1..3))
      end
    end
  end

  it 'does not crash Context#signature_from_der_encoded' do
    fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000) do |fuzzing_data|
      context.signature_from_der_encoded(fuzzing_data)
    end
  end

  it 'does not crash Context#signature_from_compact' do
    fuzz_random_binary_data(10_000, min_bytes: 0, max_bytes: 1000) do |fuzzing_data|
      context.signature_from_compact(fuzzing_data)
    end
  end
end
