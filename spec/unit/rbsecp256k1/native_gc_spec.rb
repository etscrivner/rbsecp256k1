# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Native operations with temporary inputs under GC' do
  def with_gc
    previous_stress = GC.stress
    previous_compaction = GC.auto_compact if GC.respond_to?(:auto_compact)
    GC.auto_compact = true if GC.respond_to?(:auto_compact=)
    GC.stress = true
    yield
  ensure
    GC.stress = previous_stress
    GC.auto_compact = previous_compaction if GC.respond_to?(:auto_compact=)
  end

  it 'parses temporary strings, including embedded DER and heap-backed keys' do
    context = Secp256k1::Context.create
    pair = context.key_pair_from_private_key('a' * 32)
    signature = context.sign(pair.private_key, 'b' * 32)
    parsed = with_gc do
      [Secp256k1::PrivateKey.from_data(('a' * 32).dup),
       Secp256k1::PublicKey.from_data(pair.public_key.compressed.dup),
       Secp256k1::XOnlyPublicKey.from_data(pair.xonly_public_key.serialized.dup),
       Secp256k1::Signature.from_compact(signature.compact.dup),
       Secp256k1::Signature.from_der_encoded(signature.der_encoded.dup),
       Secp256k1::Signature.from_der_encoded("\x30\x06\x02\x01\x01\x02\x01\x01".b)]
    end
    expect(parsed[0].data).to eq('a' * 32)
    expect(parsed[1]).to eq(pair.public_key)
    expect(parsed[2]).to eq(pair.xonly_public_key)
    expect(parsed[3]).to eq(signature)
    expect(parsed[4]).to eq(signature)
    expect(parsed[5].compact).to eq(([0] * 31 + [1]).pack('C*') * 2)
  end

  it 'signs, converts, copies, and serializes temporary native objects' do
    values = with_gc do
      context = Secp256k1::Context.new(context_randomization_bytes: 'c' * 32)
      pair = context.key_pair_from_private_key('a' * 32)
      signature = context.sign(pair.private_key.dup, 'b' * 32)
      normalized = Secp256k1::Signature.from_compact(signature.compact).normalized.last
      [context.verify(normalized, pair.public_key.dup, 'b' * 32),
       pair.dup.public_key.to_xonly.serialized,
       pair.clone.private_key.data,
       signature.clone.compact,
       (context.ecdh(pair.public_key, pair.private_key).data if Secp256k1.have_ecdh?)]
    end
    expect(values[0]).to be(true)
    expect(values[1].bytesize).to eq(32)
    expect(values[2]).to eq('a' * 32)
    expect(values[3].bytesize).to eq(64)
    expect(values[4].bytesize).to eq(32) if Secp256k1.have_ecdh?
  end

  it 'parses, copies, converts, and recovers temporary recoverable signatures' do
    skip 'recovery module disabled' unless Secp256k1.have_recovery?
    context = Secp256k1::Context.create
    pair = context.key_pair_from_private_key('a' * 32)
    values = with_gc do
      signature = context.sign_recoverable(pair.private_key, 'b' * 32)
      compact, recovery_id = signature.compact
      parsed = context.recoverable_signature_from_compact(compact.dup, recovery_id)
      [parsed.dup.recover_public_key('b' * 32), parsed.clone.to_signature.compact]
    end
    expect(values[0]).to eq(pair.public_key)
    expect(values[1]).to eq(context.sign(pair.private_key, 'b' * 32).compact)
  end

  it 'signs and verifies empty, embedded, and heap-backed Schnorr messages' do
    skip 'Schnorr module disabled' unless Secp256k1.have_schnorr?
    context = Secp256k1::Context.create
    pair = context.key_pair_from_private_key('a' * 32)
    verified = with_gc do
      ['', 'short', 'm' * 128].map do |message|
        signature = context.sign_schnorr_custom(pair.dup, message.dup, 'd' * 32)
        Secp256k1::SchnorrSignature.from_data(signature.serialized.dup).verify(message.dup, pair.xonly_public_key)
      end
    end
    expect(verified).to eq([true, true, true])
  end
end
