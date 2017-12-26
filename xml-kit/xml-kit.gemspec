
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "xml/kit/version"

Gem::Specification.new do |spec|
  spec.name          = "xml-kit"
  spec.version       = Xml::Kit::VERSION
  spec.authors       = ["mo khan"]
  spec.email         = ["mo.khan@gmail.com"]

  spec.summary       = %q{A simple toolkit for working with XML.}
  spec.description   = %q{A simple toolkit for working with XML.}
  spec.homepage      = "http://www.mokhan.ca"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "activemodel", ">= 4.2.0"
  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "ffaker", "~> 2.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "saml-kit", "~> 0.3"
end
