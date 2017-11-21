require 'spec_helper'

RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml) }
  let(:id) { SecureRandom.uuid }
  let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:destination) { FFaker::Internet.http_url }
  let(:name_id_format) { Saml::Kit::Namespaces::EMAIL_ADDRESS }
  let(:raw_xml) do
    builder = described_class::Builder.new
    builder.id = id
    builder.now = Time.now.utc
    builder.issuer = issuer
    builder.acs_url = acs_url
    builder.name_id_format = name_id_format
    builder.destination = destination
    builder.to_xml
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql("_#{id}") }
  it { expect(subject.acs_url).to eql(acs_url) }
  it { expect(subject.name_id_format).to eql(name_id_format) }
  it { expect(subject.destination).to eql(destination) }

  describe "#to_xml" do
    subject { described_class::Builder.new(configuration: configuration) }
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
    let(:metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
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
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      builder = described_class::Builder.new
      builder.issuer = issuer
      builder.acs_url = acs_url
      xml = builder.to_xml

      allow(metadata).to receive(:matches?).and_return(false)
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'is invalid when the service provider is not known' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      builder = described_class::Builder.new
      subject = described_class.new(builder.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:provider]).to be_present
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

    it 'validates a request without a signature' do
      now = Time.now.utc
raw_xml = <<-XML
<samlp:AuthnRequest AssertionConsumerServiceURL='#{acs_url}' ID='_#{SecureRandom.uuid}' IssueInstant='#{now.iso8601}' Version='2.0' xmlns:saml='#{Saml::Kit::Namespaces::ASSERTION}' xmlns:samlp='#{Saml::Kit::Namespaces::PROTOCOL}'>
  <saml:Issuer>#{issuer}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate='true' Format='#{Saml::Kit::Namespaces::EMAIL_ADDRESS}'/>
</samlp:AuthnRequest>
XML

      subject = described_class.new(raw_xml)
      subject.signature_verified!
      expect(subject).to be_valid
    end
  end

  describe "#acs_url" do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    it 'returns the ACS in the request' do
      builder = described_class::Builder.new
      builder.acs_url = acs_url
      subject = builder.build
      expect(subject.acs_url).to eql(acs_url)
    end

    it 'returns nil' do
      builder = described_class::Builder.new
      builder.issuer = issuer
      builder.acs_url = nil
      subject = builder.build

      expect(subject.acs_url).to be_nil
    end
  end
end
