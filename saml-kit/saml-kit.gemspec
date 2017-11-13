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
  spec.homepage      = "http://www.mokhan.ca"
  spec.license       = "MIT"
  spec.required_ruby_version = '>= 2.2.0'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activemodel", "~> 5.1"
  spec.add_dependency "activesupport", "~> 5.1"
  spec.add_dependency "builder", "~> 3.2"
  spec.add_dependency "nokogiri", "~> 1.8"
  spec.add_dependency "xmldsig", "~> 0.6"
  spec.add_development_dependency "bundler", "~> 1.15"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "ffaker", "~> 2.7"
  spec.add_development_dependency "webmock", "~> 3.1"
end
