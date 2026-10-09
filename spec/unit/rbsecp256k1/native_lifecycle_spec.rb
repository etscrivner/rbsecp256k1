# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Native object lifecycle' do
  let(:context) { Secp256k1::Context.create }
  let(:key_pair) { context.key_pair_from_private_key('a' * 32) }
  let(:private_key) { key_pair.private_key }
  let(:public_key) { key_pair.public_key }
  let(:digest) { 'b' * 32 }
  let(:signature) { context.sign(private_key, digest) }

  let(:native_values) do
    values = [key_pair, private_key, public_key, key_pair.xonly_public_key, signature]
    values << context.sign_recoverable(private_key, digest) if Secp256k1.have_recovery?
    values << context.ecdh(public_key, private_key) if Secp256k1.have_ecdh?
    values << context.sign_schnorr(key_pair, 'message') if Secp256k1.have_schnorr?
    values
  end

  let(:context_calls) do
    calls = {
      key_pair_from_private_key: ['a' * 32],
      sign: [private_key, digest],
      tagged_sha256: %w[tag message],
      verify: [signature, public_key, digest]
    }
    if Secp256k1.have_recovery?
      calls[:sign_recoverable] = [private_key, digest]
      compact, recovery_id = context.sign_recoverable(private_key, digest).compact
      calls[:recoverable_signature_from_compact] = [compact, recovery_id]
    end
    calls[:ecdh] = [public_key, private_key] if Secp256k1.have_ecdh?
    calls[:sign_schnorr_custom] = [key_pair, 'message', nil] if Secp256k1.have_schnorr?
    calls
  end

  it 'rejects direct public-key construction' do
    expect { Secp256k1::PublicKey.new }.to raise_error(TypeError)
  end

  it 'rejects keypair allocation before private-key data can expose heap contents' do
    expect { Secp256k1::KeyPair.allocate }.to raise_error(TypeError)
  end

  it 'disables new and allocate for every factory-created class and its subclasses' do
    native_values.each do |value|
      [value.class, Class.new(value.class)].each do |klass|
        expect { klass.new }.to raise_error(TypeError)
        expect { klass.allocate }.to raise_error(TypeError)
      end
    end
  end

  def copyable_values
    native_values.reject { |value| Secp256k1.have_ecdh? && value.is_a?(Secp256k1::SharedSecret) }
  end

  # GC may conservatively retain discarded objects. These are GC smoke tests,
  # not assertions about when individual native allocations are destroyed.
  # Ruby maintainers explain why even repeated GC cannot guarantee collection
  # of a particular object: https://bugs.ruby-lang.org/issues/19041
  def copy_discarding_source(copy_method)
    Secp256k1::Context.create.public_send(copy_method)
  end

  def discard_native_copies(values)
    values.each do |value|
      value.dup
      value.clone
    end
  end

  def copied_native_values(copy_method)
    local_context = Secp256k1::Context.create
    pair = local_context.key_pair_from_private_key('a' * 32)
    values = [pair, pair.private_key, pair.public_key, pair.xonly_public_key,
              local_context.sign(pair.private_key, digest)]
    values << local_context.sign_recoverable(pair.private_key, digest) if Secp256k1.have_recovery?
    values << local_context.sign_schnorr(pair, 'message') if Secp256k1.have_schnorr?
    values.map { |value| value.public_send(copy_method) }
  end

  %i[dup clone].each do |method|
    it "copies keys and signatures with #{method} into usable independent objects" do
      copyable_values.each do |source|
        source.instance_variable_set(:@label, 'key')
        copy = source.public_send(method)
        expect(copy).not_to equal(source)
        expect(copy.class).to eq(source.class)
        expect(copy.instance_variable_get(:@label)).to eq('key')
        if Secp256k1.have_recovery? && source.is_a?(Secp256k1::RecoverableSignature)
          expect(copy.compact).to eq(source.compact)
          expect(copy.recover_public_key(digest)).to eq(public_key)
        else
          expect(copy).to eq(source)
        end
        expect(source.public_send(method).frozen?).to be false
        source.freeze
        expect(source.public_send(method).frozen?).to eq(method == :clone)
        expect(source.clone(freeze: false).frozen?).to be false
      end
    end

    it "keeps #{method} copies usable across GC after discarding their sources" do
      copies = copied_native_values(method)
      GC.start
      expect(copies[0].private_key).to eq(private_key)
      expect(context.sign(copies[1], digest)).to eq(signature)
      expect(context.verify(copies[4], copies[2], digest)).to be true
      expect(copies[3].serialized).to eq(key_pair.xonly_public_key.serialized)
      copies.drop(5).each do |value|
        if Secp256k1.have_recovery? && value.is_a?(Secp256k1::RecoverableSignature)
          expect(value.recover_public_key(digest)).to eq(public_key)
        else
          expect(value.verify('message', copies[3])).to be true
        end
      end
    end
  end

  it 'rejects native access when low-level allocation bypasses the public factory boundary' do
    copyable_values.each do |source|
      empty = Class.instance_method(:allocate).bind_call(source.class)
      expect do
        empty.send(:initialize_copy, empty.dup)
      end.to raise_error(Secp256k1::Error, 'native object is not initialized')
      expect do
        context.sign(empty, digest) if empty.is_a?(Secp256k1::PrivateKey)
        empty.public_key if empty.is_a?(Secp256k1::KeyPair)
        empty.compressed if empty.is_a?(Secp256k1::PublicKey)
        empty.serialized if empty.is_a?(Secp256k1::XOnlyPublicKey) ||
                            (Secp256k1.have_schnorr? && empty.is_a?(Secp256k1::SchnorrSignature))
        empty.compact if empty.is_a?(Secp256k1::Signature) ||
                         (Secp256k1.have_recovery? && empty.is_a?(Secp256k1::RecoverableSignature))
      end.to raise_error(Secp256k1::Error, 'native object is not initialized')
    end
  end

  it 'rejects overwriting initialized native values and permits self-copy' do
    copyable_values.each do |source|
      expect(source.send(:initialize_copy, source)).to equal(source)
      expect do
        source.send(:initialize_copy, source.dup)
      end.to raise_error(Secp256k1::Error, 'native object is already initialized')
    end
  end

  it 'preserves clone singleton methods and guards skipped copy hooks' do
    source = public_key
    def source.label
      'public key'
    end
    expect(source.clone.label).to eq('public key')
    expect(source.dup).not_to respond_to(:label)
    def source.initialize_copy(_other); end
    empty = source.clone
    expect { empty.compressed }.to raise_error(Secp256k1::Error, 'native object is not initialized')
    expect { context.verify(signature, empty, digest) }.to raise_error(Secp256k1::Error)
  end

  it 'keeps original keys and signatures usable across GC after discarding copies' do
    sources = copyable_values
    discard_native_copies(sources)
    GC.start
    expect(context.sign(private_key, digest)).to eq(signature)
    expect(context.verify(signature, public_key, digest)).to be true
    expect(key_pair.private_key).to eq(private_key)
    if Secp256k1.have_recovery?
      expect(sources.grep(Secp256k1::RecoverableSignature).first.recover_public_key(digest)).to eq(public_key)
    end
  end

  it 'continues to reject shared-secret copying' do
    next unless Secp256k1.have_ecdh?

    secret = context.ecdh(public_key, private_key)
    expect { secret.dup }.to raise_error(TypeError)
    expect { secret.clone }.to raise_error(TypeError)
  end

  %i[dup clone].each do |copy_method|
    describe "Context##{copy_method}" do
      it 'creates a distinct context that can generate keys, sign, and verify' do
        copy = context.public_send(copy_method)
        expect(copy).not_to equal(context)
        expect(copy.key_pair_from_private_key('a' * 32).public_key).to eq(public_key)
        expect(copy.sign(private_key, digest)).to eq(signature)
        expect(copy.verify(signature, public_key, digest)).to be true
      end

      it 'preserves subclass type and Ruby instance variables' do
        klass = Class.new(Secp256k1::Context) { attr_accessor :label }
        source = klass.create
        source.label = 'component'
        copy = source.public_send(copy_method)
        expect(copy).to be_an_instance_of(klass)
        expect(copy.label).to eq('component')
        expect(copy.verify(signature, public_key, digest)).to be true
      end

      it 'preserves Ruby frozen-object copy semantics' do
        context.freeze
        copy = context.public_send(copy_method)
        expect(copy.frozen?).to eq(copy_method == :clone)
        expect(copy.verify(signature, public_key, digest)).to be true
      end

      it 'remains usable across GC after discarding the original context' do
        copy = copy_discarding_source(copy_method)
        GC.start
        expect(copy.key_pair_from_private_key('a' * 32).public_key).to eq(public_key)
        expect(copy.verify(signature, public_key, digest)).to be true
      end

      it 'leaves the original usable across GC after discarding the copied context' do
        context.public_send(copy_method)
        GC.start
        expect(context.verify(signature, public_key, digest)).to be true
      end

      it 'rejects copying an uninitialized context' do
        expect do
          Secp256k1::Context.allocate.public_send(copy_method)
        end.to raise_error(Secp256k1::Error, 'context is not initialized')
      end
    end
  end

  it 'treats context self-copy as a no-op and rejects overwriting an initialized context' do
    expect(context.send(:initialize_copy, context)).to equal(context)
    expect do
      context.send(:initialize_copy, Secp256k1::Context.create)
    end.to raise_error(Secp256k1::Error, 'context is already initialized')
    expect(context.verify(signature, public_key, digest)).to be true
  end

  it 'rejects every native operation on an uninitialized context' do
    # A regression to a native abort will terminate the runner. Isolated crash
    # diagnostics remain available separately in scripts/security_audit.rb.
    skipped_initialize = Class.new(Secp256k1::Context) do
      def initialize; end
    end.new

    [Secp256k1::Context.allocate, skipped_initialize].each do |uninitialized|
      context_calls.each do |method, arguments|
        expect do
          uninitialized.public_send(method, *arguments)
        end.to raise_error(Secp256k1::Error, 'context is not initialized')
      end
    end
  end

  it 'rejects native operations after initialization fails and permits a valid retry' do
    uninitialized = Secp256k1::Context.allocate
    expect do
      uninitialized.send(:initialize, context_randomization_bytes: 'short')
    end.to raise_error(Secp256k1::Error)
    expect do
      uninitialized.key_pair_from_private_key('a' * 32)
    end.to raise_error(Secp256k1::Error, 'context is not initialized')

    uninitialized.send(:initialize, context_randomization_bytes: 'c' * 32)
    derived = uninitialized.key_pair_from_private_key('a' * 32)
    expect(derived.public_key).to eq(public_key)
  end

  it 'rejects reinitialization without invalidating the existing context' do
    expect { context.send(:initialize) }.to raise_error(Secp256k1::Error, 'context is already initialized')
    expect(context.verify(signature, public_key, digest)).to be true

    uninitialized = Secp256k1::Context.allocate.freeze
    expect { uninitialized.send(:initialize) }.to raise_error(FrozenError)
  end

  it 'preserves valid factories, serialization, recovery, Schnorr signing, and ECDH' do
    expect(Secp256k1::PrivateKey.from_data(private_key.data)).to eq(private_key)
    expect(Secp256k1::PublicKey.from_data(public_key.compressed)).to eq(public_key)
    expect(Secp256k1::XOnlyPublicKey.from_data(key_pair.xonly_public_key.serialized)).to eq(key_pair.xonly_public_key)
    expect(context.verify(Secp256k1::Signature.from_compact(signature.compact), public_key, digest)).to be true
    if Secp256k1.have_recovery?
      recovered = context.sign_recoverable(private_key, digest)
      compact, recovery_id = recovered.compact
      parsed = context.recoverable_signature_from_compact(compact, recovery_id)
      expect(parsed.recover_public_key(digest)).to eq(public_key)
    end
    if Secp256k1.have_schnorr?
      signed = context.sign_schnorr(key_pair, 'message')
      parsed = Secp256k1::SchnorrSignature.from_data(signed.serialized)
      expect(parsed.verify('message', key_pair.xonly_public_key)).to be true
    end
    if Secp256k1.have_ecdh?
      expect(context.ecdh(public_key, private_key).data.bytesize).to eq(32)
    end
    subclass = Class.new(Secp256k1::Context).new
    expect(subclass.verify(signature, public_key, digest)).to be true
  end
end
