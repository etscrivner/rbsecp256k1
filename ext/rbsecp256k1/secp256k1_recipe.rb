# frozen_string_literal: true

require 'mini_portile2'
require 'zip'

# Enable the recovery module by default
WITH_RECOVERY = ENV.fetch('WITH_RECOVERY', '1') == '1'

# Recipe for downloading and building libsecp256k1 as part of installation
class Secp256k1Recipe < MiniPortile
  # Hard-coded URL for libsecp256k1 zipfile (Official release v0.8.0)
  LIBSECP256K1_ZIP_URL = 'https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.8.0.zip'

  # Expected SHA-256 of the zipfile above (computed using sha256sum)
  LIBSECP256K1_SHA256 = 'ecece6a1cec8bdecdccbf22e1ee65455feae1a5312913bd62c45bbdc912b442c'

  def initialize
    super('libsecp256k1', '0.8.0')
    @tarball = File.join(Dir.pwd, "/ports/archives/libsecp256k1.zip")
    @files = ["file://#{@tarball}"]
    self.configure_options += [
      "--with-pic=yes"
    ]

    # MiniPortile builds a static library. Its benchmark consumers also need
    # this definition on Windows to avoid references to DLL import symbols.
    if RUBY_PLATFORM =~ /mingw|mswin/
      configure_options << "CPPFLAGS=#{ENV.fetch('CPPFLAGS', '')} -DSECP256K1_STATIC"
    end

    # ECDH, extrakeys and schnorrsig are enabled by default in release v0.8.0,
    # but recovery still needs to be enabled manually.
    configure_options << "--enable-module-recovery" if WITH_RECOVERY
  end

  def configure
    # Need to run autogen.sh before configure since it creates it
    if RUBY_PLATFORM =~ /mingw|mswin/
      # Windows doesn't recognize the shebang.
      execute('autogen', %w[sh ./autogen.sh])
    else
      execute('chmod', %w[chmod +x ./autogen.sh])
      execute('autogen', %w[./autogen.sh])
    end

    super
  end

  def download
    download_file_http(LIBSECP256K1_ZIP_URL, @tarball)
    verify_file(local_path: @tarball, sha256: LIBSECP256K1_SHA256)
  end

  def downloaded?
    File.exist?(@tarball)
  end

  def extract_zip_file(file, destination)
    FileUtils.mkdir_p(destination)

    Zip::File.open(file) do |zip_file|
      zip_file.each do |f|
        fpath = File.join(destination, f.name)
        zip_file.extract(f, fpath) unless File.exist?(fpath)
      end
    end
  end

  def extract
    files_hashs.each do |file|
      # Cached and interrupted downloads also reach extraction without download.
      verify_file(local_path: file[:local_path], sha256: LIBSECP256K1_SHA256)
      extract_zip_file(file[:local_path], tmp_path)
    end
  end
end
