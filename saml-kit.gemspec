# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'saml/kit/version'

Gem::Specification.new do |spec|
  spec.name          = 'saml-kit'
  spec.version       = Saml::Kit::VERSION
  spec.authors       = ['mo khan']
  spec.email         = ['mo@mokhan.ca']

  spec.summary       = 'A simple toolkit for working with SAML.'
  spec.description   = 'A simple toolkit for working with SAML.'
  spec.homepage      = 'https://github.com/xlgmokha/saml-kit'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 3.1.0'

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    (
      f.match(%r{^(test|spec|features)/}) ||
      f.match(/^\..*/) ||
      f.match(%r{^bin/.*})
    ) && !f.match(%r{^spec/examples.*/})
  end
  spec.metadata['yard.run'] = 'yri'
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'activemodel', '>= 5.1'
  spec.add_dependency 'base64', '~> 0.1'
  spec.add_dependency 'cgi', '~> 0.1'
  spec.add_dependency 'forwardable', '~> 1.0'
  spec.add_dependency 'logger', '~> 1.0'
  spec.add_dependency 'net-hippie', '~> 1.0'
  spec.add_dependency 'nokogiri', '~> 1.0'
  spec.add_dependency 'securerandom', '~> 0.1'
  spec.add_dependency 'uri', '~> 1.0'
  spec.add_dependency 'xml-kit', '~> 0.4'
  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_development_dependency 'bundler-audit', '~> 0.6'
  spec.add_development_dependency 'erb', '~> 4.0'
  spec.add_development_dependency 'ffaker', '~> 2.7'
  spec.add_development_dependency 'irb', '~> 1.0'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rspec-benchmark', '~> 0.3'
  spec.add_development_dependency 'rubocop', '~> 1.0'
  spec.add_development_dependency 'rubocop-rspec', '~> 3.0'
  spec.add_development_dependency 'ruby-prof'
  spec.add_development_dependency 'simplecov', '~> 0.15'
  spec.add_development_dependency 'webmock', '~> 3.1'
end
