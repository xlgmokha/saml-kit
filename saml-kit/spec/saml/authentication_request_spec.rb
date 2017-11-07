require 'spec_helper'

RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml) }
  let(:id) { SecureRandom.uuid }
  let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:name_id_format) { Saml::Kit::Namespaces::EMAIL_ADDRESS }
  let(:raw_xml) do
    builder = described_class::Builder.new
    builder.id = id
    builder.issued_at = Time.now.utc
    builder.issuer = issuer
    builder.acs_url = acs_url
    builder.name_id_format = name_id_format
    builder.to_xml
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql("_#{id}") }
  it { expect(subject.acs_url).to eql(acs_url) }
  it { expect(subject.name_id_format).to eql(name_id_format) }

  describe "#to_xml" do
    subject { described_class::Builder.new(configuration) }
    let(:configuration) do
      config = Saml::Kit::Configuration.new
      config.issuer = issuer
      config
    end
    let(:issuer) { FFaker::Movie.title }
    let(:acs_url) { "https://airport.dev/session/acs" }

    it 'returns a valid authentication request' do
      travel_to 1.second.from_now
      subject.acs_url = acs_url
      result = Hash.from_xml(subject.to_xml)

      expect(result['AuthnRequest']['ID']).to be_present
      expect(result['AuthnRequest']['Version']).to eql('2.0')
      expect(result['AuthnRequest']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(result['AuthnRequest']['AssertionConsumerServiceURL']).to eql(acs_url)
      expect(result['AuthnRequest']['Issuer']).to eql(issuer)
      expect(result['AuthnRequest']['NameIDPolicy']['Format']).to eql(Saml::Kit::Namespaces::PERSISTENT)
    end
  end

  describe "#valid?" do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:service_provider_metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(service_provider_metadata)
      allow(service_provider_metadata).to receive(:matches?).and_return(true)
    end

    it 'is valid when left untampered' do
      subject = described_class.new(raw_xml)
      expect(subject).to be_valid
    end

    it 'is invalid if the document has been tampered with' do
      raw_xml.gsub!(issuer, 'corrupt')
      subject = described_class.new(raw_xml)
      expect(subject).to be_invalid
    end

    it 'is invalid when blank' do
      subject = described_class.new('')
      expect(subject).to be_invalid
      expect(subject.errors[:content]).to be_present
    end

    it 'is invalid when not an AuthnRequest' do
      xml = Saml::Kit::IdentityProviderMetadata::Builder.new.to_xml
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to be_present
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      builder = described_class::Builder.new
      builder.issuer = issuer
      builder.acs_url = acs_url
      xml = builder.to_xml

      allow(service_provider_metadata).to receive(:matches?).and_return(false)
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'is invalid when the service provider is not known' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      builder = described_class::Builder.new
      subject = described_class.new(builder.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:service_provider]).to be_present
    end

    it 'is invalid when an assertion consumer service url is not provided' do
      allow(service_provider_metadata).to receive(:matches?).and_return(true)
      allow(service_provider_metadata).to receive(:assertion_consumer_services).and_return([])

      builder = described_class::Builder.new
      builder.acs_url = nil
      xml = builder.to_xml

      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:acs_url]).to be_present
    end

    it 'is valid when an the ACS is available via the registry' do
      allow(registry).to receive(:metadata_for).with(issuer)
        .and_return(service_provider_metadata)
      allow(service_provider_metadata).to receive(:matches?).and_return(true)
      allow(service_provider_metadata).to receive(:assertion_consumer_services).and_return([
        { location: acs_url, binding: Saml::Kit::Namespaces::POST }
      ])

      builder = described_class::Builder.new
      builder.issuer = issuer
      builder.acs_url = nil
      xml = builder.to_xml

      expect(described_class.new(xml)).to be_valid
    end

    it 'validates the schema of the request' do
      xml = ::Builder::XmlMarkup.new
      id = SecureRandom.uuid
      options = {
        "xmlns:samlp" => Saml::Kit::Namespaces::PROTOCOL,
        AssertionConsumerServiceURL: acs_url,
        ID: "_#{id}",
      }
      signature = Saml::Kit::Signature.new(id)
      xml.tag!('samlp:AuthnRequest', options) do
        signature.template(xml)
        xml.Fake do
          xml.NotAllowed "Huh?"
        end
      end
      expect(described_class.new(signature.finalize(xml))).to be_invalid
    end
  end

  describe "#acs_url" do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:service_provider_metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    it 'returns the ACS in the request' do
      builder = described_class::Builder.new
      builder.acs_url = acs_url
      subject = builder.build
      expect(subject.acs_url).to eql(acs_url)
    end

    it 'returns the registered ACS url' do
      builder = described_class::Builder.new
      builder.issuer = issuer
      builder.acs_url = nil
      subject = builder.build

      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(service_provider_metadata)
      allow(registry).to receive(:metadata_for).with(issuer).and_return(service_provider_metadata)
      allow(service_provider_metadata).to receive(:assertion_consumer_services).and_return([
        { location: acs_url, binding: Saml::Kit::Namespaces::POST }
      ])
      expect(subject.acs_url).to eql(acs_url)
    end
  end
end
