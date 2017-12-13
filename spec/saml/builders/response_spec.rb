require 'spec_helper'

RSpec.describe Saml::Kit::Builders::Response do
  subject { described_class.new(user, request) }
  let(:email) { FFaker::Internet.email }
  let(:assertion_consumer_service_url) { FFaker::Internet.uri("https") }
  let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: { email: email, created_at: Time.now.utc.iso8601 }) }
  let(:request) { double(:request, id: Saml::Kit::Id.generate, assertion_consumer_service_url: assertion_consumer_service_url, issuer: issuer, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: provider, trusted?: true, signed?: true) }
  let(:provider) { double(want_assertions_signed: false, encryption_certificates: [Saml::Kit::Certificate.new(encryption_pem, use: :encryption)]) }
  let(:encryption_pem) { Saml::Kit.configuration.encryption_certificate.stripped }
  let(:issuer) { FFaker::Internet.uri("https") }

  before :each do
    allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
  end

  describe "#build" do
    it 'builds a response with the request_id' do
      expect(subject.build.request_id).to eql(request.id)
    end

    it 'builds a valid encrypted assertion' do
      allow(Saml::Kit.configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)
      allow(provider).to receive(:matches?).and_return(true)

      subject.sign = true
      subject.encrypt = true
      result = subject.build
      expect(result).to be_valid
    end
  end

  describe "#to_xml" do
    it 'returns a proper response for the user' do
      travel_to 1.second.from_now
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
      subject.destination = assertion_consumer_service_url
      subject.encrypt = false
      hash = Hash.from_xml(subject.to_xml)

      expect(hash['Response']['ID']).to be_present
      expect(hash['Response']['Version']).to eql('2.0')
      expect(hash['Response']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(hash['Response']['Destination']).to eql(assertion_consumer_service_url)
      expect(hash['Response']['InResponseTo']).to eql(request.id)
      expect(hash['Response']['Issuer']).to eql(issuer)
      expect(hash['Response']['Status']['StatusCode']['Value']).to eql("urn:oasis:names:tc:SAML:2.0:status:Success")

      expect(hash['Response']['Assertion']['ID']).to be_present
      expect(hash['Response']['Assertion']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(hash['Response']['Assertion']['Version']).to eql("2.0")
      expect(hash['Response']['Assertion']['Issuer']).to eql(issuer)

      expect(hash['Response']['Assertion']['Subject']['NameID']).to eql(user.name_id_for)
      expect(hash['Response']['Assertion']['Subject']['SubjectConfirmation']['Method']).to eql("urn:oasis:names:tc:SAML:2.0:cm:bearer")
      expect(hash['Response']['Assertion']['Subject']['SubjectConfirmation']['SubjectConfirmationData']['NotOnOrAfter']).to eql(3.hours.from_now.utc.iso8601)
      expect(hash['Response']['Assertion']['Subject']['SubjectConfirmation']['SubjectConfirmationData']['Recipient']).to eql(assertion_consumer_service_url)
      expect(hash['Response']['Assertion']['Subject']['SubjectConfirmation']['SubjectConfirmationData']['InResponseTo']).to eql(request.id)

      expect(hash['Response']['Assertion']['Conditions']['NotBefore']).to eql(0.seconds.ago.utc.iso8601)
      expect(hash['Response']['Assertion']['Conditions']['NotOnOrAfter']).to eql(3.hours.from_now.utc.iso8601)
      expect(hash['Response']['Assertion']['Conditions']['AudienceRestriction']['Audience']).to eql(request.issuer)

      expect(hash['Response']['Assertion']['AuthnStatement']['AuthnInstant']).to eql(Time.now.utc.iso8601)
      expect(hash['Response']['Assertion']['AuthnStatement']['SessionNotOnOrAfter']).to eql(3.hours.from_now.utc.iso8601)
      expect(hash['Response']['Assertion']['AuthnStatement']['SessionIndex']).to eql(hash['Response']['Assertion']['ID'])
      expect(hash['Response']['Assertion']['AuthnStatement']['AuthnContext']['AuthnContextClassRef']).to eql('urn:oasis:names:tc:SAML:2.0:ac:classes:Password')

      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][0]['Name']).to eql('email')
      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][0]['FriendlyName']).to eql('email')
      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][0]['NameFormat']).to eql('urn:oasis:names:tc:SAML:2.0:attrname-format:uri')
      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][0]['AttributeValue']).to eql(email)

      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][1]['Name']).to eql('created_at')
      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][1]['FriendlyName']).to eql('created_at')
      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][1]['NameFormat']).to eql('urn:oasis:names:tc:SAML:2.0:attrname-format:uri')
      expect(hash['Response']['Assertion']['AttributeStatement']['Attribute'][1]['AttributeValue']).to be_present
    end

    it 'does not add a signature when the SP does not want assertions signed' do
      builder = Saml::Kit::Builders::ServiceProviderMetadata.new
      builder.want_assertions_signed = false
      metadata = builder.build
      allow(request).to receive(:provider).and_return(metadata)

      hash = Hash.from_xml(subject.to_xml)
      expect(hash['Response']['Signature']).to be_nil
    end

    it 'generates an EncryptedAssertion' do
      subject.encrypt = true
      result = Hash.from_xml(subject.to_xml)
      expect(result['Response']['EncryptedAssertion']).to be_present
      encrypted_assertion = result['Response']['EncryptedAssertion']
      decrypted_assertion = Saml::Kit::XmlDecryption.new.decrypt(encrypted_assertion)
      decrypted_hash = Hash.from_xml(decrypted_assertion)
      expect(decrypted_hash['Assertion']).to be_present
      expect(decrypted_hash['Assertion']['Issuer']).to be_present
      expect(decrypted_hash['Assertion']['Subject']).to be_present
      expect(decrypted_hash['Assertion']['Subject']['NameID']).to be_present
      expect(decrypted_hash['Assertion']['Subject']['SubjectConfirmation']).to be_present
      expect(decrypted_hash['Assertion']['Conditions']).to be_present
      expect(decrypted_hash['Assertion']['Conditions']['AudienceRestriction']).to be_present
      expect(decrypted_hash['Assertion']['AuthnStatement']).to be_present
      expect(decrypted_hash['Assertion']['AuthnStatement']['AuthnContext']).to be_present
      expect(decrypted_hash['Assertion']['AuthnStatement']['AuthnContext']['AuthnContextClassRef']).to be_present
    end

    it 'generates a signed response and encrypted assertion' do
      subject.encrypt = true
      subject.sign = true
      result = Hash.from_xml(subject.to_xml)
      expect(result['Response']['Signature']).to be_present
      expect(result['Response']['EncryptedAssertion']).to be_present
    end

    it 'generates a signed response and assertion' do
      subject.encrypt = false
      subject.sign = true
      result = Hash.from_xml(subject.to_xml)
      expect(result['Response']['Signature']).to be_present
      expect(result['Response']['Assertion']['Signature']).to be_present
    end
  end
end
