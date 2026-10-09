# frozen_string_literal: true

require "rake/extensiontask"
require "ruby_memcheck"
require "rspec/core/rake_task"
require 'ruby_memcheck/rspec/rake_task'
require 'shellwords'

memcheck_options = RubyMemcheck::Configuration::DEFAULT_VALGRIND_OPTIONS.dup
if ENV['MEMCHECK_DEBUGINFO_PATH']
  memcheck_options << "--extra-debuginfo-path=#{Shellwords.escape(File.expand_path(ENV['MEMCHECK_DEBUGINFO_PATH']))}"
end
RubyMemcheck.config(binary_name: "rbsecp256k1", valgrind_options: memcheck_options)

# See: https://guides.rubygems.org/gems-with-extensions/
Rake::ExtensionTask.new "rbsecp256k1" do |ext|
  ext.lib_dir = 'lib/rbsecp256k1'
end

RSpec::Core::RakeTask.new(:spec)
namespace :spec do
  RubyMemcheck::RSpec::RakeTask.new(valgrind: :spec)
end
