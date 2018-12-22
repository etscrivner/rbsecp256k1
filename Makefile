.PHONY: setup build test lint gem install uninstall clean

setup:
	bundle install

build:
	bundle exec rake compile

test: build
	bundle exec rspec

lint:
	bundle exec rubocop

gem:
	gem build rbsecp256k1.gemspec

install: gem
	gem install rbsecp256k1-0.1.0.gem

uninstall:
	gem uninstall rbsecp256k1

clean:
	rm -rf *~ rbsecp256k1-0.1.0.gem lib/rbsecp256k1/rbsecp256k1.so tmp
