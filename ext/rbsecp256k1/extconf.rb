require 'mini_portile2'
require 'mkmf'
require 'zip'

# Indicates the platform on which the package is being installed
INSTALLING_OS =
  if RUBY_PLATFORM =~ /darwin/
    :macos
  elsif RUBY_PLATFORM =~ /linux/
    :linux
  else
    :unknown
  end

# Fixed path to Homebrew OpenSSL pkgconfig file
HOMEBREW_OPENSSL_PKGCONFIG = '/usr/local/opt/openssl/lib/pkgconfig'.freeze

# Recipe for downloading and building libsecp256k1 as part of installation
class Secp256k1Recipe < MiniPortile
  # Hard-coded URL for libsecp256k1 zipfile (HEAD of master as of 26-11-2018)
  LIBSECP256K1_ZIP_URL = 'https://github.com/bitcoin-core/secp256k1/archive/e34ceb333b1c0e6f4115ecbb80c632ac1042fa49.zip'.freeze

  # Expected SHA-256 of the zipfile above (computed using sha256sum)
  LIBSECP256K1_SHA256 = 'd87d3ca7ebc42edbabb0f38e79205040b24b09b3e6d1c9ac89585de9bf302143'.freeze

  WITH_RECOVERY = ENV.fetch('WITH_RECOVERY', '1') == '1'
  WITH_ECDH = ENV.fetch('WITH_ECDH', '1') == '1'

  def initialize
    super('libsecp256k1', '0.0.0')
    @tarball = File.join(Dir.pwd, "/ports/archives/libsecp256k1.zip")
    @files = ["file://#{@tarball}"]
    self.configure_options += [
      "--disable-benchmark",
      "--disable-exhaustive-tests",
      "--disable-tests",
      "--disable-debug",
      "--enable-experimental",
      "--with-pic=yes"
    ]

    configure_options << "--enable-module-recovery" if WITH_RECOVERY
    configure_options << "--enable-module-ecdh" if WITH_ECDH
  end

  def configure
    # Need to run autogen.sh before configure since it creates it
    if RUBY_PLATFORM =~ /mingw|mswin/
      # Windows doesn't recognize the shebang.
      execute('autogen', %w[sh ./autogen.sh])
    else
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
      extract_zip_file(file[:local_path], tmp_path)
    end
  end
end

# OpenSSL flags
message("checking for OpenSSL\n")
results = pkg_config('openssl')

# Failed to find package OpenSSL
unless results && results[1]
  # Check if the user happens to have OpenSSL installed via Homebrew on a path
  # we know about.
  # rubocop:disable Style/GlobalVars
  if INSTALLING_OS == :macos && File.exist?(HOMEBREW_OPENSSL_PKGCONFIG)
    begin
      require 'rubygems'
      gem 'pkg-config', (gem_ver = '~> 1.3')
      require 'pkg-config'
    rescue LoadError
      message(
        "pkg-config could not be used to find openssl\n" \
        "Please install either `pkg-config` or the pkg-config gem via\n" \
        "gem install pkg-config -v #{gem_ver.inspect}\n\n"
      )
    else
      message("Initial check failed. Trying homebrew openssl path...\n")
      message("Using pkg-config gem version #{PKGConfig::VERSION}\n")
      PKGConfig.add_path(HOMEBREW_OPENSSL_PKGCONFIG)

      cflags = PKGConfig.cflags('openssl')
      ldflags = PKGConfig.libs_only_L('openssl')
      libs = PKGConfig.libs_only_l('openssl')

      $CFLAGS += " " << cflags if cflags
      $libs += " " << libs if libs
      $LDFLAGS = [$LDFLAGS, ldflags].join(' ')

      results = [cflags, libs, ldflags]
    end
  end
  # rubocop:enable Style/GlobalVars
end
abort "missing openssl pkg-config information" unless results && results[1]

if with_config('system-library')
  # Require that libsecp256k1 be installed using `make install` or similar.
  message("checking for libsecp256k1\n")
  results = pkg_config('libsecp256k1')
  abort "missing libsecp256k1" unless results && results[1]
else
  # Build the libsecp256k1 dependency
  recipe = Secp256k1Recipe.new
  recipe.cook
  recipe.activate

  # Need to add paths to includes and libraries for library for build
  append_cflags(
    [
      "-I#{recipe.path}/include",
      "-fPIC",
      "-Wno-undef",
      "-Wall"
    ]
  )
  # rubocop:disable Style/GlobalVars
  $LIBPATH = ["#{recipe.path}/lib"] | $LIBPATH
  # rubocop:enable Style/GlobalVars

  # Also need to make sure we add the library as part of the build
  have_library("secp256k1")
  have_library("gmp")
end

# Check if we have the libsecp256k1 recoverable signature header.
have_header('secp256k1_recovery.h')

# Check if we have EC Diffie-Hellman functionality
have_header('secp256k1_ecdh.h')

create_makefile('rbsecp256k1')
