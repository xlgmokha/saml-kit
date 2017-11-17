require 'spec_helper'

RSpec.describe Saml::Kit::Binding do
  let(:location) { FFaker::Internet.http_url }
  subject { Saml::Kit::Binding.new(binding: Saml::Kit::Namespaces::HTTP_ARTIFACT, location: location) }

  describe "#serialize" do
    it 'ignores other bindings' do
      expect(subject.serialize(Saml::Kit::AuthenticationRequest)).to be_empty
    end
  end

  describe "#deserialize" do
    it 'raises an error' do
      expect do
        subject.deserialize('SAMLRequest' => "CORRUPT")
      end.to raise_error(/Unsupported binding/)
    end
  end
end
