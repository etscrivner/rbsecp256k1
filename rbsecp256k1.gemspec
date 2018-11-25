$LOAD_PATH.push(File.expand_path('lib', __dir__))
require 'rbsecp256k1/version'

Gem::Specification.new do |s|
  s.name    = 'rbsecp256k1'
  s.version = Secp256k1::VERSION
  s.summary = 'Compiled, native ruby interfaces to libsecp256k1'
  s.license = 'BSD'
  s.authors = ['Eric Scrivner']

  s.files = Dir['lib/**/**.rb'] + %w[ext/rbsecp256k1/rbsecp256k1.c ext/rbsecp256k1/extconf.rb Rakefile]
  s.require_paths = ['ext', 'lib']

  s.extensions = ['ext/rbsecp256k1/extconf.rb']
end
