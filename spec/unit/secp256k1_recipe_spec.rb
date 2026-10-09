# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require 'digest'
require_relative '../../ext/rbsecp256k1/secp256k1_recipe'

RSpec.describe Secp256k1Recipe do
  around do |example|
    Dir.mktmpdir('secp256k1-recipe') do |directory|
      @directory = directory
      Dir.chdir(directory) { example.run }
    end
  end

  let(:archive) { File.join(@directory, 'libsecp256k1.zip') }
  let(:destination) { 'extracted' }
  let(:recipe) do
    described_class.new.tap do |instance|
      instance.instance_variable_set(:@tarball, archive)
      instance.files = ["file://#{archive}"]
      allow(instance).to receive(:archives_path).and_return(@directory)
      allow(instance).to receive(:tmp_path).and_return(destination)
    end
  end

  before do
    Zip::File.open(archive, create: true) do |zip|
      zip.mkdir('secp256k1')
      zip.get_output_stream('secp256k1/README') { |stream| stream.write('fixture source') }
    end
    # Exercise real SHA-256 verification with a small local archive.
    stub_const('Secp256k1Recipe::LIBSECP256K1_SHA256', Digest::SHA256.file(archive).hexdigest)
  end

  it 'builds from a valid cached archive without downloading' do
    expect(recipe).not_to receive(:download)
    %i[patch configure compile install].each { |step| allow(recipe).to receive(step) }

    recipe.cook

    expect(File.read(File.join(destination, 'secp256k1/README'))).to eq('fixture source')
  end

  it 'rejects a modified cached ZIP before extracting or building' do
    Zip::File.open(archive) do |zip|
      zip.get_output_stream('secp256k1/README') { |stream| stream.write('modified source') }
    end
    expect(recipe).not_to receive(:download)
    %i[extract_zip_file patch configure compile install].each do |step|
      expect(recipe).not_to receive(step)
    end

    expect { recipe.cook }.to raise_error(RuntimeError, /wrong hash/)
    expect(File.exist?(destination)).to be(false)
  end

  it 'rejects a partial cached download before opening it as a ZIP' do
    File.binwrite(archive, File.binread(archive)[0, 16])
    expect(recipe).not_to receive(:extract_zip_file)

    expect { recipe.extract }.to raise_error(RuntimeError, /wrong hash/)
    expect(File.exist?(destination)).to be(false)
  end

  it 'checks again if an archive is modified after a successful download' do
    allow(recipe).to receive(:download_file_http)
    recipe.download
    File.open(archive, 'ab') { |file| file.write('modified after download') }
    expect(recipe).not_to receive(:extract_zip_file)

    expect { recipe.extract }.to raise_error(RuntimeError, /wrong hash/)
  end

  it 'packages the recipe needed by extconf' do
    gemspec = Gem::Specification.load(File.expand_path('../../rbsecp256k1.gemspec', __dir__))
    expect(gemspec.files).to include('ext/rbsecp256k1/secp256k1_recipe.rb')
  end

  it 'configures Windows static-library consumers without discarding caller flags' do
    stub_const('RUBY_PLATFORM', 'x64-mingw-ucrt')
    original_flags = ENV['CPPFLAGS']
    begin
      ENV['CPPFLAGS'] = '-DUSER_BUILD_FLAG=1'
      expect(recipe.configure_options).to include('CPPFLAGS=-DUSER_BUILD_FLAG=1 -DSECP256K1_STATIC')
    ensure
      ENV['CPPFLAGS'] = original_flags
    end
  end
end
