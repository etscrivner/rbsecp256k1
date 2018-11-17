$LOAD_PATH.push(File.expand_path('lib', __dir__))
require 'rbsecp256k1/version'

Gem::Specification.new do |s|
  s.name    = 'rbsecp256k1'
  s.version = Secp256k1::VERSION
  s.summary = 'Compiled, native ruby interfaces to libsecp256k1'
  s.license = 'BSD'
  s.authors = ['Eric Scrivner']

  s.files = Dir['lib/**.rb']
  s.require_paths = ['lib']

  s.add_dependency 'pkg-config'

  s.extensions = ['ext/rbsecp256k1/extconf.rb']
end
