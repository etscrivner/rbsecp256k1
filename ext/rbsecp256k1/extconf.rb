require 'mkmf'

# Use pkg-config. Lifted from nokogiri.
def package_config(pkg, options={})
  package = pkg_config(pkg)
  return package if package

  begin
    require 'rubygems'
    gem 'pkg-config', (gem_ver='~> 1.1')
    require 'pkg-config' and message("Using pkg-config gem version #{PKGConfig::VERSION}\n")
  rescue LoadError
    message "pkg-config could not be used to find #{pkg}\nPlease install either `pkg-config` or the pkg-config gem per\n\n    gem install pkg-config -v #{gem_ver.inspect}\n\n"
  else
    return nil unless PKGConfig.have_package(pkg)

    cflags  = PKGConfig.cflags(pkg)
    ldflags = PKGConfig.libs_only_L(pkg)
    libs    = PKGConfig.libs_only_l(pkg)

    Logging::message "PKGConfig package configuration for %s\n", pkg
    Logging::message "cflags: %s\nldflags: %s\nlibs: %s\n\n", cflags, ldflags, libs

    [cflags, ldflags, libs]
  end
end

# OpenSSL flags
results = package_config('openssl')
abort "missing openssl pkg-config information" unless results

append_cflags(results[0])
append_ldflags(results[1])

# Require that libsecp256k1 be installed using `make install` or similar.
abort "missing libsecp256k1" unless have_library('secp256k1')

create_makefile('rbsecp256k1')
