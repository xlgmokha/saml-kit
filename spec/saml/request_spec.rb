require 'spec_helper'

RSpec.describe Saml::Kit::Request do
  describe ".deserialize" do
    subject { described_class }
    let(:issuer) { FFaker::Internet.http_url }
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:service_provider_metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(service_provider_metadata)
      allow(service_provider_metadata).to receive(:matches?).and_return(true)
      allow(service_provider_metadata).to receive(:assertion_consumer_services).and_return([
        { location: FFaker::Internet.http_url, binding: Saml::Kit::Namespaces::POST }
      ])
    end

    it 'decodes the raw_request' do
      builder = Saml::Kit::AuthenticationRequest::Builder.new
      builder.issuer = issuer
      raw_saml = builder.build.serialize

      result = subject.deserialize(raw_saml)
      expect(result.issuer).to eql(issuer)
      expect(result).to be_valid
    end

    it 'returns an invalid request when the raw request is corrupted' do
      expect(subject.deserialize("nonsense")).to be_invalid
    end

    it 'returns a logout request' do
      user = double(:user, name_id_for: SecureRandom.uuid)
      builder = Saml::Kit::LogoutRequest::Builder.new(user)

      result = subject.deserialize(builder.build.serialize)
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
      expect(result.name_id).to eql(user.name_id_for)
    end
  end
end
