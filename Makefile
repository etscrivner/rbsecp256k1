.PHONY: build clean docker docserver gem install lint memcheck setup test uninstall

all: test

build:
	$(COMPILE_PREFIX) bundle exec rake compile

clean:
	rm -rf *~ rbsecp256k1-*.gem lib/rbsecp256k1/rbsecp256k1.so tmp .yardoc

docker:
	docker build -t rbsecp256k1 .

docserver:
	bundle exec yard server --reload

gem:
	gem build rbsecp256k1.gemspec

install: gem
	gem install rbsecp256k1-*.gem

lint:
	bundle exec rubocop

memcheck: build
	valgrind --trace-children=yes --num-callers=50 --error-limit=no --partial-loads-ok=yes --undef-value-errors=no --error-exitcode=42 --gen-suppressions=all --max-stackframe=8382656 bundle exec rspec

memcheck-docker: docker
	docker run rbsecp256k1 /bin/sh -c "make memcheck"

setup:
	bundle install

test: build
	bundle exec rspec

uninstall:
	gem uninstall rbsecp256k1
