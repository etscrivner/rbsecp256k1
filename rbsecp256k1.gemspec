$LOAD_PATH.push(File.expand_path('lib', __dir__))
require 'secpruby/version'

Gem::Specification.new do |s|
  s.name    = 'secpruby'
  s.version = SecpRuby::VERSION
  s.summary = 'Compiled, native ruby interfaces to libsecp256k1'
  s.license = 'BSD'
  s.authors = ['Eric Scrivner']

  s.files = Dir['lib/**.rb']
  s.require_paths = ['lib']

  s.extensions = ['ext/secpruby/extconf.rb']
end
