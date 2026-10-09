# frozen_string_literal: true

require 'spec_helper'
require 'objspace'

RSpec.describe 'Native memory reporting' do
  let(:context) { Secp256k1::Context.create }
  let(:pair) { context.key_pair_from_private_key('a' * 32) }
  let(:digest) { 'b' * 32 }

  def empty_shell(klass)
    Class.instance_method(:allocate).bind_call(klass)
  end

  it 'reports inline native storage in addition to the Ruby object' do
    values = [
      [pair, 96], [pair.private_key, 32], [pair.public_key, 64],
      [pair.xonly_public_key, 64], [context.sign(pair.private_key, digest), 64]
    ]
    values << [context.ecdh(pair.public_key, pair.private_key), 32] if Secp256k1.have_ecdh?
    values << [context.sign_schnorr(pair, 'message'), 64] if Secp256k1.have_schnorr?

    values.each do |value, bytes|
      # SharedSecret has no allocator. Match its Ruby instance-variable storage
      # on an empty typed-data shell; the referenced string is counted separately.
      shell_class = Secp256k1.have_ecdh? && value.is_a?(Secp256k1::SharedSecret) ? Secp256k1::PrivateKey : value.class
      shell = empty_shell(shell_class)
      value.instance_variables.each { |name| shell.instance_variable_set(name, nil) }
      expect(ObjectSpace.memsize_of(value) - ObjectSpace.memsize_of(shell)).to eq(bytes), value.class.name
    end
  end

  it 'includes the owned context allocation only after initialization' do
    empty = Secp256k1::Context.allocate
    ruby_bytes = ObjectSpace.memsize_of(empty_shell(Secp256k1::PrivateKey))
    expect(ObjectSpace.memsize_of(empty) - ruby_bytes).to eq([0].pack('J').bytesize)
    expect(ObjectSpace.memsize_of(context)).to be > ObjectSpace.memsize_of(empty)
  end

  it 'reports the same owned memory for independently copied contexts' do
    expect(ObjectSpace.memsize_of(context)).to be > ObjectSpace.memsize_of(Secp256k1::Context.allocate)
    %i[dup clone].each do |method|
      expect(ObjectSpace.memsize_of(context.public_send(method))).to eq(ObjectSpace.memsize_of(context))
    end
  end

  it 'includes the context owned by recoverable signatures and their copies' do
    skip 'recovery module disabled' unless Secp256k1.have_recovery?
    signature = context.sign_recoverable(pair.private_key, digest)
    shell_bytes = ObjectSpace.memsize_of(empty_shell(signature.class))
    context_bytes = ObjectSpace.memsize_of(context) - ObjectSpace.memsize_of(Secp256k1::Context.allocate)
    expect(ObjectSpace.memsize_of(signature) - shell_bytes).to be >= 65 + [0].pack('J').bytesize + context_bytes
    %i[dup clone].each do |method|
      expect(ObjectSpace.memsize_of(signature.public_send(method))).to eq(ObjectSpace.memsize_of(signature))
    end
  end
end
