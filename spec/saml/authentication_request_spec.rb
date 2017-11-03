require 'spec_helper'

RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml) }
  let(:id) { SecureRandom.uuid }
  let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:raw_xml) do
    builder = described_class::Builder.new
    builder.id = id
    builder.issued_at = Time.now.utc
    builder.issuer = issuer
    builder.acs_url = acs_url
    builder.to_xml
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql("_#{id}") }
  it { expect(subject.acs_url).to eql(acs_url) }

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
      travel_to DateTime.new(2014, 7, 16, 23, 52, 45)
      subject.acs_url = acs_url
      result = Hash.from_xml(subject.to_xml)

      expect(result['AuthnRequest']['ID']).to be_present
      expect(result['AuthnRequest']['Version']).to eql('2.0')
      expect(result['AuthnRequest']['IssueInstant']).to eql('2014-07-16T23:52:45Z')
      expect(result['AuthnRequest']['AssertionConsumerServiceURL']).to eql(acs_url)
      expect(result['AuthnRequest']['Issuer']).to eql(issuer)
      expect(result['AuthnRequest']['NameIDPolicy']['Format']).to eql("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    end
  end

  describe "#valid?" do
    let(:registry) { double }

    it 'is valid when left untampered' do
      expect(described_class.new(raw_xml)).to be_valid
    end

    it 'is invalid if the document has been tampered with' do
      raw_xml.gsub!(issuer, 'corrupt')
      subject = described_class.new(raw_xml)
      expect(subject).to_not be_valid
    end

    it 'is invalid when blank' do
      expect(described_class.new('')).to be_invalid
    end

    it 'is invalid when not an AuthnRequest' do
      xml = Saml::Kit::IdentityProviderMetadata::Builder.new.to_xml
      expect(described_class.new(xml)).to be_invalid
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      builder = described_class::Builder.new
      builder.issuer = issuer
      xml = builder.to_xml

      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      fingerprint = Saml::Kit::Fingerprint.new(Hash.from_xml(xml)['AuthnRequest']['Signature']['KeyInfo']['X509Data']['X509Certificate'])
      allow(registry).to receive(:registered?).with(issuer, fingerprint).and_return(false)
      expect(described_class.new(xml)).to be_invalid
    end
  end
end
