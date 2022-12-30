# frozen_string_literal: true

# Wraps libsecp256k1 in a ruby module and provides object interfaces.
module Secp256k1
end

require 'rbsecp256k1/context'
require 'rbsecp256k1/util'
require 'rbsecp256k1/version'

# The ext directory is where the compiled shared object files go for native
# extension gems. Rubygems adds this to the LOAD_PATH so we should just need to
# explicitly require the shared object
require 'rbsecp256k1/rbsecp256k1'
