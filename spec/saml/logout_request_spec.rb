require 'spec_helper'

RSpec.describe Saml::Kit::LogoutRequest do
  subject { builder.build }
  let(:builder) { described_class::Builder.new(user) }
  let(:user) { double(:user, name_id_for: name_id) }
  let(:name_id) { SecureRandom.uuid }

  it 'parses the issuer' do
    builder.issuer = FFaker::Internet.http_url
    expect(subject.issuer).to eql(builder.issuer)
  end

  it 'parses the issue instant' do
    travel_to 1.second.from_now
    expect(subject.issue_instant).to eql(Time.now.utc.iso8601)
  end

  it 'parses the version' do
    expect(subject.version).to eql("2.0")
  end

  it 'parses the destination' do
    builder.destination = FFaker::Internet.http_url
    expect(subject.destination).to eql(builder.destination)
  end

  it 'parses the name_id' do
    expect(subject.name_id).to eql(name_id)
  end

  describe "#valid?" do
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::ServiceProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      allow(metadata).to receive(:single_logout_services).and_return([
        { location: FFaker::Internet.http_url, binding: Saml::Kit::Namespaces::POST }
      ])
    end

    it 'is valid when left untampered' do
      expect(builder.build).to be_valid
    end

    it 'is invalid if the document has been tampered with' do
      builder.issuer = FFaker::Internet.http_url
      raw_xml = builder.to_xml.gsub(builder.issuer, 'corrupt')
      subject = described_class.new(raw_xml)
      expect(subject).to be_invalid
    end

    it 'is invalid when blank' do
      subject = described_class.new('')
      expect(subject).to be_invalid
      expect(subject.errors[:content]).to be_present
    end

    it 'is invalid when not a LogoutRequest' do
      xml = Saml::Kit::IdentityProviderMetadata::Builder.new.to_xml
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(metadata).to receive(:matches?).and_return(false)
      subject = builder.build
      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'is invalid when the provider is not known' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = builder.build
      expect(subject).to be_invalid
      expect(subject.errors[:provider]).to be_present
    end

    it 'is invalid when single logout service url is not provided' do
      allow(metadata).to receive(:matches?).and_return(true)
      allow(metadata).to receive(:single_logout_services).and_return([])

      subject = builder.build
      expect(subject).to be_invalid
      expect(subject.errors[:single_logout_service]).to be_present
    end

    it 'is valid when a single lgout service url is available via the registry' do
      builder.issuer = FFaker::Internet.http_url
      allow(registry).to receive(:metadata_for).with(builder.issuer).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      allow(metadata).to receive(:single_logout_services).and_return([
        { location: FFaker::Internet.http_url, binding: Saml::Kit::Namespaces::POST }
      ])

      expect(builder.build).to be_valid
    end

    it 'validates the schema of the request' do
      id = SecureRandom.uuid
      signature = Saml::Kit::Signature.new(id)
      xml = ::Builder::XmlMarkup.new
      xml.LogoutRequest ID: "_#{id}" do
        signature.template(xml)
        xml.Fake do
          xml.NotAllowed "Huh?"
        end
      end
      expect(described_class.new(signature.finalize(xml))).to be_invalid
    end
  end

  describe described_class::Builder do
    subject { described_class.new(user) }
    let(:user) { double(:user, name_id_for: name_id) }
    let(:name_id) { SecureRandom.uuid }

    it 'produces the expected xml' do
      travel_to 1.second.from_now
      subject.id = SecureRandom.uuid
      subject.destination = FFaker::Internet.http_url
      subject.issuer = FFaker::Internet.http_url
      subject.name_id_format = Saml::Kit::Namespaces::TRANSIENT

      result = subject.to_xml
      xml_hash = Hash.from_xml(result)

      expect(xml_hash['LogoutRequest']['ID']).to eql("_#{subject.id}")
      expect(xml_hash['LogoutRequest']['Version']).to eql("2.0")
      expect(xml_hash['LogoutRequest']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(xml_hash['LogoutRequest']['Destination']).to eql(subject.destination)

      expect(xml_hash['LogoutRequest']['Issuer']).to eql(subject.issuer)
      expect(xml_hash['LogoutRequest']['NameID']).to eql(name_id)
      expect(result).to have_xpath("//samlp:LogoutRequest//saml:NameID[@Format=\"#{subject.name_id_format}\"]")
    end

    it 'includes a signature by default' do
      xml_hash = Hash.from_xml(subject.to_xml)
      expect(xml_hash['LogoutRequest']['Signature']).to be_present
    end

    it 'excludes a signature' do
      subject.sign = false
      xml_hash = Hash.from_xml(subject.to_xml)
      expect(xml_hash['LogoutRequest']['Signature']).to be_nil
    end

    it 'builds a LogoutRequest' do
      travel_to 1.second.from_now
      result = subject.build
      expect(result).to be_instance_of(Saml::Kit::LogoutRequest)
      expect(result.to_xml).to eql(subject.to_xml)
    end
  end

  describe "#response_for" do
    it 'returns a logout response for a particular user' do
      user = double(:user)
      expect(subject.response_for(user)).to be_instance_of(Saml::Kit::LogoutResponse::Builder)
    end
  end
end
