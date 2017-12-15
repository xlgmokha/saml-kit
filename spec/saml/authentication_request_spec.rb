require 'spec_helper'

RSpec.describe Saml::Kit::AuthenticationRequest do
  subject { described_class.new(raw_xml, configuration: configuration) }
  let(:id) { Saml::Kit::Id.generate }
  let(:assertion_consumer_service_url) { "https://#{FFaker::Internet.domain_name}/acs" }
  let(:issuer) { FFaker::Movie.title }
  let(:destination) { FFaker::Internet.http_url }
  let(:name_id_format) { Saml::Kit::Namespaces::EMAIL_ADDRESS }
  let(:raw_xml) do
    described_class.build_xml(configuration: configuration) do |builder|
      builder.id = id
      builder.now = Time.now.utc
      builder.issuer = issuer
      builder.assertion_consumer_service_url = assertion_consumer_service_url
      builder.name_id_format = name_id_format
      builder.destination = destination
    end
  end
  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.generate_key_pair_for(use: :signing)
    end
  end

  it { expect(subject.issuer).to eql(issuer) }
  it { expect(subject.id).to eql(id) }
  it { expect(subject.assertion_consumer_service_url).to eql(assertion_consumer_service_url) }
  it { expect(subject.name_id_format).to eql(name_id_format) }
  it { expect(subject.destination).to eql(destination) }

  describe "#valid?" do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { Saml::Kit::ServiceProviderMetadata.build(configuration: configuration) }

    before :each do
      allow(configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(metadata)
    end

    it 'is valid when left untampered' do
      subject = described_class.new(raw_xml, configuration: configuration)
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
        builder.assertion_consumer_service_url = assertion_consumer_service_url
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
      id = Saml::Kit::Id.generate
      configuration = Saml::Kit::Configuration.new
      configuration.generate_key_pair_for(use: :signing)
      signed_xml = Saml::Kit::Signature.sign(configuration: configuration) do |xml, signature|
        xml.tag!('samlp:AuthnRequest', "xmlns:samlp" => Saml::Kit::Namespaces::PROTOCOL, AssertionConsumerServiceURL: assertion_consumer_service_url, ID: id) do
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
<samlp:AuthnRequest AssertionConsumerServiceURL='#{assertion_consumer_service_url}' ID='#{Saml::Kit::Id.generate}' IssueInstant='#{now.iso8601}' Version='2.0' xmlns:saml='#{Saml::Kit::Namespaces::ASSERTION}' xmlns:samlp='#{Saml::Kit::Namespaces::PROTOCOL}'>
  <saml:Issuer>#{issuer}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate='true' Format='#{Saml::Kit::Namespaces::EMAIL_ADDRESS}'/>
</samlp:AuthnRequest>
      XML

      subject = described_class.new(raw_xml, configuration: configuration)
      subject.signature_verified!
      expect(subject).to be_valid
    end
  end

  describe "#assertion_consumer_service_url" do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    it 'returns the ACS in the request' do
      subject = described_class.build do |builder|
        builder.assertion_consumer_service_url = assertion_consumer_service_url
      end
      expect(subject.assertion_consumer_service_url).to eql(assertion_consumer_service_url)
    end

    it 'returns nil' do
      subject = described_class.build do |builder|
        builder.assertion_consumer_service_url = nil
      end

      expect(subject.assertion_consumer_service_url).to be_nil
    end
  end

  describe ".build" do
    let(:url) { FFaker::Internet.uri("https") }
    let(:entity_id) { FFaker::Internet.uri("https") }

    it 'provides a nice API for building metadata' do
      result = described_class.build do |builder|
        builder.issuer = entity_id
        builder.assertion_consumer_service_url = url
      end

      expect(result).to be_instance_of(described_class)
      expect(result.issuer).to eql(entity_id)
      expect(result.assertion_consumer_service_url).to eql(url)
    end
  end

  describe "#response_for" do
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: []) }
    let(:provider) do
      Saml::Kit::ServiceProviderMetadata.build do |x|
        x.add_assertion_consumer_service(FFaker::Internet.uri("https"), binding: :http_post)
      end
    end

    it 'serializes a response' do
      allow(subject).to receive(:provider).and_return(provider)
      url, saml_params = subject.response_for(user, binding: :http_post, relay_state: FFaker::Movie.title)

      response = provider.assertion_consumer_service_for(binding: :http_post).deserialize(saml_params)
      expect(response).to be_instance_of(Saml::Kit::Response)
    end
  end
end
