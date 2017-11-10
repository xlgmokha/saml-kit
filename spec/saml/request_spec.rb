require 'spec_helper'

RSpec.describe Saml::Kit::Request do
  describe ".encode" do
    subject { described_class }

    it 'returns a compressed and base64 encoded document' do
      xml = "<xml></xml>"
      document = double(to_xml: xml)

      expected_value = Base64.encode64(Zlib::Deflate.deflate(xml, 9)).gsub(/\n/, '')
      expect(subject.encode(document)).to eql(expected_value)
    end
  end

  describe ".decode" do
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
      raw_saml = subject.encode(builder)

      result = subject.decode(raw_saml)
      expect(result.issuer).to eql(issuer)
      expect(result).to be_valid
    end

    it 'returns an invalid request when the raw request is corrupted' do
      expect(subject.decode("nonsense")).to be_invalid
    end
  end
end
