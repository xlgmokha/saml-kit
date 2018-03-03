
# frozen_string_literal: true

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'saml/kit/version'

Gem::Specification.new do |spec|
  spec.name          = 'saml-kit'
  spec.version       = Saml::Kit::VERSION
  spec.authors       = ['mo khan']
  spec.email         = ['mo@mokhan.ca']

  spec.summary       = 'A simple toolkit for working with SAML.'
  spec.description   = 'A simple toolkit for working with SAML.'
  spec.homepage      = 'https://github.com/saml-kit/saml-kit'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.2.0'

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

  spec.add_dependency 'activemodel', '>= 4.2.0'
  spec.add_dependency 'xml-kit', '>= 0.1.12', '<= 1.0.0'
  spec.add_development_dependency 'bundler', '~> 1.15'
  spec.add_development_dependency 'bundler-audit', '~> 0.6'
  spec.add_development_dependency 'ffaker', '~> 2.7'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rspec-benchmark', '~> 0.3'
  spec.add_development_dependency 'rubocop', '~> 0.52'
  spec.add_development_dependency 'rubocop-rspec', '~> 1.22'
  spec.add_development_dependency 'ruby-prof'
  spec.add_development_dependency 'simplecov', '~> 0.15'
  spec.add_development_dependency 'webmock', '~> 3.1'
end
