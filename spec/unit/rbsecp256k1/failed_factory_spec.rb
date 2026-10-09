# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Native objects left by failed factories' do
  # Keep rejected factory objects alive long enough to inspect their state.
  # This tests validity, not whether GC collects a particular object on demand.
  def objects_created_by(klass)
    previously_disabled = GC.disable
    before_ids = ObjectSpace.each_object(klass).map(&:object_id)
    yield
    ObjectSpace.each_object(klass).reject { |object| before_ids.include?(object.object_id) }
  ensure
    GC.enable unless previously_disabled
  end

  def expect_uninitialized(object, method)
    expect { object.public_send(method) }.to raise_error(Secp256k1::Error, 'native object is not initialized')
    expect { object.dup }.to raise_error(Secp256k1::Error, 'native object is not initialized')
  end

  it 'invalidates rejected public keys before serialization or copying' do
    objects = objects_created_by(Secp256k1::PublicKey) do
      expect { Secp256k1::PublicKey.from_data("\x00" * 33) }.to raise_error(Secp256k1::DeserializationError)
    end
    expect(objects.length).to eq(1)
    expect_uninitialized(objects.first, :compressed)
  end

  it 'invalidates rejected x-only public keys' do
    objects = objects_created_by(Secp256k1::XOnlyPublicKey) do
      expect { Secp256k1::XOnlyPublicKey.from_data("\xff" * 32) }.to raise_error(Secp256k1::DeserializationError)
    end
    expect(objects.length).to eq(1)
    expect_uninitialized(objects.first, :serialized)
  end

  it 'invalidates rejected keypairs before exposing keys' do
    context = Secp256k1::Context.create
    objects = objects_created_by(Secp256k1::KeyPair) do
      expect { context.key_pair_from_private_key("\x00" * 32) }.to raise_error(Secp256k1::Error)
    end
    expect(objects.length).to eq(1)
    expect_uninitialized(objects.first, :public_key)
    expect { objects.first.private_key }.to raise_error(Secp256k1::Error, 'native object is not initialized')
  end

  it 'invalidates rejected compact and DER signatures' do
    objects = objects_created_by(Secp256k1::Signature) do
      expect { Secp256k1::Signature.from_compact("\xff" * 64) }.to raise_error(Secp256k1::DeserializationError)
      expect { Secp256k1::Signature.from_der_encoded('invalid') }.to raise_error(Secp256k1::DeserializationError)
    end
    expect(objects.length).to eq(2)
    objects.each { |object| expect_uninitialized(object, :compact) }
  end

  it 'invalidates rejected recoverable signatures and failed recovery outputs' do
    skip 'recovery module disabled' unless Secp256k1.have_recovery?
    context = Secp256k1::Context.create
    objects = objects_created_by(Secp256k1::RecoverableSignature) do
      expect { context.recoverable_signature_from_compact("\xff" * 64, 0) }.to raise_error(Secp256k1::DeserializationError)
    end
    expect(objects.length).to eq(1)
    expect_uninitialized(objects.first, :compact)

    signature = context.recoverable_signature_from_compact("\x00" * 64, 0)
    public_keys = objects_created_by(Secp256k1::PublicKey) do
      expect { signature.recover_public_key('a' * 32) }.to raise_error(Secp256k1::DeserializationError)
    end
    expect(public_keys.length).to eq(1)
    expect_uninitialized(public_keys.first, :compressed)
  end
end
