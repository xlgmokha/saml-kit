require 'spec_helper'

RSpec.describe Saml::Kit::DefaultRegistry do
  subject { described_class.new }
  let(:entity_id) { FFaker::Internet.http_url }
  let(:service_provider_metadata) do
    builder = Saml::Kit::ServiceProviderMetadata::Builder.new
    builder.entity_id = entity_id
    builder.build
  end
  let(:identity_provider_metadata) do
    builder = Saml::Kit::IdentityProviderMetadata::Builder.new
    builder.entity_id = entity_id
    builder.build
  end

  describe "#metadata_for" do
    it 'returns the metadata for the entity_id' do
      subject.register(service_provider_metadata)
      expect(subject.metadata_for(entity_id)).to eql(service_provider_metadata)
    end
  end

  describe "#register_url" do
    let(:url) { FFaker::Internet.http_url }

    it 'fetches the SP metadata from a remote url and registers it' do
      stub_request(:get, url).
        to_return(status: 200, body: service_provider_metadata.to_xml)
      subject.register_url(url)

      result = subject.metadata_for(entity_id)
      expect(result).to be_present
      expect(result).to be_instance_of(Saml::Kit::ServiceProviderMetadata)
    end

    it 'fetches the IDP metadata from a remote url' do
      stub_request(:get, url).
        to_return(status: 200, body: identity_provider_metadata.to_xml)
      subject.register_url(url)

      result = subject.metadata_for(entity_id)
      expect(result).to be_present
      expect(result).to be_instance_of(Saml::Kit::IdentityProviderMetadata)
    end
  end

  xit 'registers metadata that serves as both an IDP and SP'
end
