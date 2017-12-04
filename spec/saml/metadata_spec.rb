require 'spec_helper'

RSpec.describe Saml::Kit::Metadata do
  describe ".from" do
    subject { described_class }

    it 'returns an identity provider metadata' do
      xml = Saml::Kit::IdentityProviderMetadata.build.to_xml
      expect(subject.from(xml)).to be_instance_of(Saml::Kit::IdentityProviderMetadata)
    end

    it 'returns a service provider metadata' do
      xml = Saml::Kit::ServiceProviderMetadata.build.to_xml
      expect(subject.from(xml)).to be_instance_of(Saml::Kit::ServiceProviderMetadata)
    end
  end
end
