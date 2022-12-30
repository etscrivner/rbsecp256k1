# frozen_string_literal: true

$LOAD_PATH.push(File.expand_path('lib', __dir__))
require 'rbsecp256k1/version'

Gem::Specification.new do |s|
  s.name    = 'rbsecp256k1'
  s.version = Secp256k1::VERSION
  s.summary =
    'Native extension gem for secp256k1 ECDSA. Wraps libsecp256k1. In ' \
    'rbsecp256k1 3.0.0 and later libsecp256k1 is bundled with the gem.'
  s.license = 'MIT'
  s.authors = ['Eric Scrivner']
  s.homepage = 'https://github.com/etscrivner/rbsecp256k1'

  s.files = (
    Dir['lib/**/**.rb'] +
    Dir['documentation/**.md'] +
    %w[ext/rbsecp256k1/rbsecp256k1.c ext/rbsecp256k1/extconf.rb Rakefile README.md]
  )
  s.require_paths = %w[ext lib]

  s.extensions = ['ext/rbsecp256k1/extconf.rb']

  # Dependencies required to build and run this gem
  s.add_dependency 'mini_portile2', '~> 2.8'
  s.add_dependency 'pkg-config', '~> 1.5'
  s.add_dependency 'rubyzip', '~> 2.3'

  # Development dependencies
  s.add_development_dependency 'rake', '~> 13.0'
  s.add_development_dependency 'rake-compiler', '~> 1.2'
  s.add_development_dependency 'rspec', '~> 3.8'
  s.add_development_dependency 'rubocop', '0.78'
  s.add_development_dependency 'ruby_memcheck', '~> 1.2'
  s.add_development_dependency 'yard', '~> 0.9'
end
