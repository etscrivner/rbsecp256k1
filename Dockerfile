FROM ruby:3.2

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y apt-utils build-essential

RUN apt-get install -y valgrind
RUN apt-get install -y ruby ruby-dev bundler
RUN gem install bundler

RUN mkdir /app

COPY Gemfile rbsecp256k1.gemspec /app/
COPY Gemfile* /app/
COPY Makefile /app/
COPY Rakefile /app/
COPY *.gemspec /app/
COPY valgrind-memcheck.patch /app/
COPY ./lib /app/lib
COPY ./ext /app/ext
COPY ./spec /app/spec

WORKDIR /app
RUN bundle install
