# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "saml/kit/version"

Gem::Specification.new do |spec|
  spec.name          = "saml-kit"
  spec.version       = Saml::Kit::VERSION
  spec.authors       = ["mo khan"]
  spec.email         = ["mo@mokhan.ca"]

  spec.summary       = %q{A simple toolkit for working with SAML.}
  spec.description   = %q{A simple toolkit for working with SAML.}
  spec.homepage      = "https://github.com/saml-kit/saml-kit"
  spec.license       = "MIT"
  spec.required_ruby_version = '>= 2.2.0'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.metadata["yard.run"] = "yri"
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activemodel", ">= 4.2.0"
  spec.add_dependency "xml-kit", ">= 0.1.9", "<= 1.0.0"
  spec.add_development_dependency "bundler", "~> 1.15"
  spec.add_development_dependency "ffaker", "~> 2.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov", "~> 0.15.1"
  spec.add_development_dependency "webmock", "~> 3.1"
end
