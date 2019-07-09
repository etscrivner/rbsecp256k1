FROM ruby:2.5

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y apt-utils build-essential

RUN apt-get install -y valgrind
RUN apt-get install -y ruby ruby-dev bundler
RUN gem install bundler

RUN mkdir /app

COPY Gemfile rbsecp256k1.gemspec /app/
COPY . /app

WORKDIR /app
RUN bundle install
