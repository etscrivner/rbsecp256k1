FROM ruby:3.4-trixie

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y apt-utils build-essential automake libtool pkg-config libgmp-dev

RUN apt-get install -y valgrind libc6-dbg
RUN gem install bundler

RUN mkdir /app

COPY Gemfile rbsecp256k1.gemspec /app/
COPY Gemfile* /app/
COPY Makefile /app/
COPY Rakefile /app/
COPY *.gemspec /app/
COPY ./lib /app/lib
COPY ./ext /app/ext
COPY ./spec /app/spec

WORKDIR /app
RUN bundle install
