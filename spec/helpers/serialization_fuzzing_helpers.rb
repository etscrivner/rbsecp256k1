# frozen_string_literal: true

# Shared by parser fuzzing and regression tests of the harness itself.
module SerializationFuzzingHelpers
  def random_binary_data(min_size, max_size)
    random.bytes(random.rand(min_size..max_size))
  end

  def fuzz_random_binary_data(iterations, min_bytes:, max_bytes:, corpus: [])
    raise ArgumentError, 'corpus exceeds iteration budget' if corpus.length > iterations

    counts = { attempted: 0, accepted: 0, rejected: 0 }
    iterations.times do |index|
      data = corpus.fetch(index) { random_binary_data(min_bytes, max_bytes) }
      counts[:attempted] += 1
      begin
        yield data
        counts[:accepted] += 1
      rescue Secp256k1::Error => e
        raise_fuzz_failure(e, index, data) unless expected_parse_error?(e)
        counts[:rejected] += 1
      rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
        raise_fuzz_failure(e, index, data)
      end
    end
    counts
  end

  def expected_parse_error?(error)
    # Current parsers use the base Error for length checks and
    # DeserializationError for malformed contents. Serialization failures
    # after parsing must escape rather than count as rejected input.
    error.instance_of?(Secp256k1::Error) || error.is_a?(Secp256k1::DeserializationError)
  end

  def raise_fuzz_failure(error, index, data)
    replay = "seed=#{seed} iteration=#{index} bytes=#{data.bytesize} hex=#{data.unpack1('H*')}"
    raise error, "#{error.message} (#{replay})", error.backtrace
  end
end
