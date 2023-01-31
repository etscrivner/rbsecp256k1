# frozen_string_literal: true

require 'spec_helper'
require 'digest/keccak'

if Secp256k1.have_recovery?
  # Computes the Keccak256 hash of the given data.
  #
  # @param data [String] binary or text data to be hashed.
  # @return [String] binary hash of the given data.
  def keccak256(data)
    Digest::Keccak.new(256).digest(data)
  end

  # Returns the address corresponding to the given public key.
  #
  # @param public_key_bin [String] binary public key data
  # @return [String]
  def public_key_to_address(public_key_bin)
    Secp256k1::Util.bin_to_hex(keccak256(public_key_bin[1..-1])[-20..-1])
  end

  # Represents a personal message that can be signed in Ethereum.
  class PersonalMessage
    # Default constructor.
    #
    # @param message [String] personal message to be signed or verified.
    def initialize(message)
      @message = message
    end

    def prefixed_message
      # Prepend the expected web3.eth.sign message prefix
      "\x19Ethereum Signed Message:\n#{@message.length}#{@message}"
    end

    # Signs a personal message with the given private key.
    #
    # @param private_key [Secp256k1::PrivateKey] key to use for signing.
    # @param chain_id [Integer] unique identifier for chain.
    # @return [String] binary signature data including recovery id v at end.
    def sign(private_key, chain_id)
      ctx = Secp256k1::Context.new
      signature, recovery_id = ctx.sign_recoverable(private_key, hash).compact
      result = signature.bytes
      result = result.append(Chains.to_v(recovery_id, chain_id))
      result.pack('c*')
    end

    # Produce a signature with legacy v values.
    #
    # @param private_key [Secp256k1::PrivateKey] key to use for signing.
    # @return [String] binary signature data including legacy recovery id v at end.
    def sign_legacy(private_key)
      ctx = Secp256k1::Context.new
      signature, recovery_id = ctx.sign_recoverable(private_key, hash).compact
      result = signature.bytes
      result = result.append(27 + recovery_id)
      result.pack('c*')
    end

    # Returns the keccak256 hash of the message.
    #
    # Applies the expected prefix for personal messages signed with Ethereum keys.
    #
    # @return [String] binary string hash of the given data.
    def hash
      keccak256(prefixed_message)
    end
  end

  # Encapsulates utilities and constants for various Ethereum chains.
  module Chains
    # Chain IDs for various chains (from EIP-155)
    MAINNET = 1
    MORDEN = 2
    ROPSTEN = 3
    RINKEBY = 4
    KOVAN = 42
    ETC_MAINNET = 61
    ETC_TESTNET = 62

    # Indicates whether or not the given value represents a legacy chain v.
    #
    # @return [Boolean] true if the v represents a signature before the ETC fork,
    #   false if it does not.
    def self.legacy_recovery_id?(v)
      [27, 28].include?(v)
    end

    # Convert a v value into an ECDSA recovery id.
    #
    # See EIP-155 for more information the computations done in this method:
    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
    #
    # @param v [Integer] v value from a signature.
    # @param chain_id [Integer] chain ID for the chain the signature was
    #   generated on.
    # @return [Integer] the recovery id corresponding to the given v value.
    # @raise [ArgumentError] if the given v value is invalid.
    def self.to_recovery_id(v, chain_id)
      # Handle the legacy network recovery ids
      return v - 27 if legacy_recovery_id?(v)

      if [(2 * chain_id + 35), (2 * chain_id + 36)].include?(v)
        return v - 35 - 2 * chain_id
      end

      raise ArgumentError, "Invalid v value for chain #{chain_id}. Invalid chain_id?"
    end

    # Converts a recovery ID into the expected v value.
    #
    # @param recovery_id [Integer] signature recovery id (should be 0 or 1).
    # @param chain_id [Integer] Unique ID of the Ethereum chain.
    # @return [Integer] the v value for the recovery id.
    def self.to_v(recovery_id, chain_id)
      2 * chain_id + 35 + recovery_id
    end
  end

  # Represents and recoverable Ethereum signature
  class RecoverableSignature
    # Initialize recoverable signature.
    #
    # @param signature [String] Hex of signature (should not have 0x prefix)
    # @param chain_id [Integer] (Optional) chain ID used for deriving recovery id.
    # @raise [ArgumentError] if signature is the wrong length.
    # @raise [RuntimeError] if v value derived from signature is invalid.
    def initialize(signature, chain_id = Chains::MAINNET)
      # Move the last byte containing the v value to the front.
      rotated_signature = Secp256k1::Util.hex_to_bin(signature).bytes.rotate(-1)

      if rotated_signature.length != 65
        raise ArgumentError, "invalid signature not 65 bytes in length"
      end

      @v = rotated_signature[0]

      if @v < chain_id
        raise "invalid signature v '#{@v}' is not less than #{@chain_id}."
      end

      @signature = rotated_signature[1..-1].pack('c*')
      @chain_id = chain_id
    end

    # Recover public key for this recoverable signature.
    #
    # @param message [PersonalMessage] The message to verify the signature against.
    # @return [String] public key address corresponding to the public key recovered.
    def recover_public_key(message)
      ctx = Secp256k1::Context.new
      recovery_id = Chains.to_recovery_id(@v, @chain_id)

      recoverable_signature = ctx.recoverable_signature_from_compact(@signature, recovery_id)
      public_key_bin = recoverable_signature.recover_public_key(message.hash).uncompressed
      public_key_to_address(public_key_bin)
    end
  end

  RSpec.describe Secp256k1::RecoverableSignature do
    let(:context) { Secp256k1::Context.create }
    let(:key_pair) { context.generate_key_pair }
    let(:text_message) { sha256('more test stuff') }

    describe '#compact' do
      it 'returns the compact signature and recovery id' do
        signature = context.sign_recoverable(key_pair.private_key, text_message)

        signature, recovery_id = signature.compact
        expect(signature).to be_a(String)
        expect(signature.length).to be(64)
        expect(recovery_id).to be_a(Integer)
      end
    end

    describe '#to_signature' do
      it 'returns the non-recoverable signature object' do
        recoverable_signature = context.sign_recoverable(
          key_pair.private_key, text_message
        )
        compact, = recoverable_signature.compact

        signature = recoverable_signature.to_signature
        expect(signature).to be_a(Secp256k1::Signature)
        expect(signature.compact.bytes).to eq(compact.bytes)
      end
    end

    describe '#recover_public_key' do
      it 'recovers the public key from signature' do
        recoverable_signature = context.sign_recoverable(
          key_pair.private_key, text_message
        )

        recovered_public_key = recoverable_signature.recover_public_key(
          text_message
        )

        expect(recovered_public_key).to be_a(Secp256k1::PublicKey)
        expect(recovered_public_key.compressed.bytes)
          .to eq(key_pair.public_key.compressed.bytes)
      end

      it 'bad data to result in wrong public key' do
        recoverable_signature = context.sign_recoverable(
          key_pair.private_key, text_message
        )

        public_key = recoverable_signature.recover_public_key(
          sha256('bad data')
        )

        expect(public_key).to be_a(Secp256k1::PublicKey)
        expect(public_key.compressed.bytes)
          .not_to eq(key_pair.public_key.compressed.bytes)
      end
    end

    describe 'ethereum recovery example' do
      it 'does basic signing and recovery' do
        ctx = Secp256k1::Context.new

        # Do this a few times so we generate even and odd key values
        100.times do
          key_pair = ctx.generate_key_pair
          message = PersonalMessage.new("Hello world!")

          expected_pubkey = public_key_to_address(key_pair.public_key.uncompressed)
          signature_hex = Secp256k1::Util.bin_to_hex(
            message.sign(key_pair.private_key, Chains::MAINNET)
          )
          signature = RecoverableSignature.new(signature_hex, Chains::MAINNET)

          pubkey_address = signature.recover_public_key(message)
          expect(pubkey_address).to eq(expected_pubkey)
        end
      end

      it 'does legacy signing and recovery' do
        ctx = Secp256k1::Context.new

        # Do this a few times so we generate even and odd key values
        100.times do
          key_pair = ctx.generate_key_pair
          message = PersonalMessage.new("Hello world!")

          expected_pubkey = public_key_to_address(key_pair.public_key.uncompressed)
          legacy_signature_hex = Secp256k1::Util.bin_to_hex(
            message.sign_legacy(key_pair.private_key)
          )
          legacy_signature = RecoverableSignature.new(
            legacy_signature_hex, Chains::MAINNET
          )

          legacy_pubkey_address = legacy_signature.recover_public_key(message)
          expect(legacy_pubkey_address).to eq(expected_pubkey)
        end
      end
    end
  end
end
