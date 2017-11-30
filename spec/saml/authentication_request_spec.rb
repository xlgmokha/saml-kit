require 'spec_helper'

RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml) }
  let(:id) { SecureRandom.uuid }
  let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:destination) { FFaker::Internet.http_url }
  let(:name_id_format) { Saml::Kit::Namespaces::EMAIL_ADDRESS }
  let(:raw_xml) do
    described_class.build do |builder|
      builder.id = id
      builder.now = Time.now.utc
      builder.issuer = issuer
      builder.acs_url = acs_url
      builder.name_id_format = name_id_format
      builder.destination = destination
    end.to_xml
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql("_#{id}") }
  it { expect(subject.acs_url).to eql(acs_url) }
  it { expect(subject.name_id_format).to eql(name_id_format) }
  it { expect(subject.destination).to eql(destination) }

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
      xml = Saml::Kit::IdentityProviderMetadata.build.to_xml
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(metadata).to receive(:matches?).and_return(false)
      subject = described_class.build do |builder|
        builder.issuer = issuer
        builder.acs_url = acs_url
      end

      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'is invalid when the service provider is not known' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = described_class.build
      expect(subject).to be_invalid
      expect(subject.errors[:provider]).to be_present
    end

    it 'validates the schema of the request' do
      id = SecureRandom.uuid
      signed_xml = Saml::Kit::Signature.sign(sign: true) do |xml, signature|
        xml.tag!('samlp:AuthnRequest', "xmlns:samlp" => Saml::Kit::Namespaces::PROTOCOL, AssertionConsumerServiceURL: acs_url, ID: "_#{id}") do
          signature.template(id)
          xml.Fake do
            xml.NotAllowed "Huh?"
          end
        end
      end
      expect(described_class.new(signed_xml)).to be_invalid
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
      subject = described_class.build do |builder|
        builder.acs_url = acs_url
      end
      expect(subject.acs_url).to eql(acs_url)
    end

    it 'returns nil' do
      subject = described_class.build do |builder|
        builder.acs_url = nil
      end

      expect(subject.acs_url).to be_nil
    end
  end

  describe ".build" do
    let(:url) { FFaker::Internet.uri("https") }
    let(:entity_id) { FFaker::Internet.uri("https") }

    it 'provides a nice API for building metadata' do
      result = described_class.build do |builder|
        builder.issuer = entity_id
        builder.acs_url = url
      end

      expect(result).to be_instance_of(described_class)
      expect(result.issuer).to eql(entity_id)
      expect(result.acs_url).to eql(url)
    end
  end
end
