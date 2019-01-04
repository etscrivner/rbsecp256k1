.PHONY: setup build test lint gem install uninstall clean docserver

all: test

setup:
	bundle install

build:
	$(COMPILE_PREFIX) bundle exec rake compile

test: build
	bundle exec rspec

lint:
	bundle exec rubocop

gem:
	gem build rbsecp256k1.gemspec

install: gem
	gem install rbsecp256k1-*.gem

uninstall:
	gem uninstall rbsecp256k1

clean:
	rm -rf *~ rbsecp256k1-*.gem lib/rbsecp256k1/rbsecp256k1.so tmp .yardoc

docserver:
	bundle exec yard server --reload
