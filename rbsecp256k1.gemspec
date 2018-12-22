$LOAD_PATH.push(File.expand_path('lib', __dir__))
require 'rbsecp256k1/version'

Gem::Specification.new do |s|
  s.name    = 'rbsecp256k1'
  s.version = Secp256k1::VERSION
  s.summary = 'Compiled, native ruby extension interfaces to libsecp256k1'
  s.license = 'MIT'
  s.authors = ['Eric Scrivner']
  s.homepage = 'https://github.com/etscrivner/rbsecp256k1'

  s.files = (
    Dir['lib/**/**.rb'] +
    %w[ext/rbsecp256k1/rbsecp256k1.c ext/rbsecp256k1/extconf.rb Rakefile]
  )
  s.require_paths = %w[ext lib]

  s.extensions = ['ext/rbsecp256k1/extconf.rb']

  # Development dependencies
  s.add_development_dependency 'rake', '~> 12.3'
  s.add_development_dependency 'rake-compiler', '~> 1.0'
  s.add_development_dependency 'rspec', '~> 3.8'
  s.add_development_dependency 'rubocop', '~> 0.61'
end
