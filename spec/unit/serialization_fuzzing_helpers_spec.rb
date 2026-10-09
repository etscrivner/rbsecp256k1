# frozen_string_literal: true

require 'spec_helper'
require_relative '../helpers/serialization_fuzzing_helpers'

RSpec.describe SerializationFuzzingHelpers do
  include described_class

  let(:seed) { 321 }
  let(:random) { Random.new(seed) }

  it 'executes every iteration even when every input is rejected' do
    calls = 0
    fuzz_random_binary_data(10, min_bytes: 0, max_bytes: 1000) do
      calls += 1
      raise Secp256k1::DeserializationError, 'expected rejection'
    end
    expect(calls).to eq(10)
  end

  [NameError, NoMethodError, TypeError, RuntimeError, Secp256k1::SerializationError,
   RSpec::Expectations::ExpectationNotMetError].each do |error_class|
    it "propagates #{error_class} instead of treating it as invalid input" do
      expect do
        fuzz_random_binary_data(10, min_bytes: 0, max_bytes: 1000) { raise error_class, 'programming error' }
      end.to raise_error(error_class, /programming error/)
    end
  end

  it 'counts accepted and rejected inputs separately' do
    calls = 0
    result = fuzz_random_binary_data(10, min_bytes: 0, max_bytes: 1000) do
      calls += 1
      raise Secp256k1::Error if calls.even?
    end
    expect(result).to eq(attempted: 10, accepted: 5, rejected: 5)
  end

  it 'uses only the seeded generator for input lengths and contents' do
    expect(self).not_to receive(:rand)
    expect(random_binary_data(32, 32).bytesize).to eq(32)
  end

  it 'replays exactly the same inputs with the same seed' do
    sequences = Array.new(2) do
      allow(self).to receive(:random).and_return(Random.new(seed))
      Array.new(20) { random_binary_data(0, 1000) }
    end
    expect(sequences.first).to eq(sequences.last)
  end

  it 'includes replay information when an unexpected error escapes' do
    allow(self).to receive(:random_binary_data).and_return('x'.b * 32)
    expect do
      fuzz_random_binary_data(10, min_bytes: 0, max_bytes: 1000) { raise NoMethodError, 'broken parser' }
    end.to raise_error(NoMethodError, /seed=321.*iteration=0.*bytes=32.*hex=#{'78' * 32}/m)
  end

  it 'exercises the supplied corpus before random inputs without reducing the iteration count' do
    inputs = []
    result = fuzz_random_binary_data(10, min_bytes: 32, max_bytes: 32, corpus: ['valid', ''.b]) do |input|
      inputs << input
    end
    expect(inputs.first(2)).to eq(['valid', ''.b])
    expect(inputs.drop(2).map(&:bytesize)).to eq([32] * 8)
    expect(result).to eq(attempted: 10, accepted: 10, rejected: 0)
  end
end
