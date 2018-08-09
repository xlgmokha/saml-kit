# frozen_string_literal: true

RSpec.describe Saml::Kit::Builders::Response do
  subject { described_class.new(user, request, configuration: configuration) }

  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.entity_id = issuer
      config.generate_key_pair_for(use: :signing)
      config.generate_key_pair_for(use: :encryption)
    end
  end
  let(:email) { FFaker::Internet.email }
  let(:assertion_consumer_service_url) { FFaker::Internet.uri('https') }
  let(:user) { User.new(attributes: { email: email, created_at: Time.now.utc.iso8601 }) }
  let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: Xml::Kit::Id.generate, assertion_consumer_service_url: assertion_consumer_service_url, issuer: issuer, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: provider, trusted?: true, signed?: true) }
  let(:provider) { instance_double(Saml::Kit::ServiceProviderMetadata, want_assertions_signed: false, encryption_certificates: [configuration.certificates(use: :encryption).last]) }
  let(:issuer) { FFaker::Internet.uri('https') }

  describe '#build' do
    it 'builds a response with the request_id' do
      expect(subject.build.request_id).to eql(request.id)
    end

    it 'builds a valid encrypted assertion' do
      allow(configuration.registry).to receive(:metadata_for).with(issuer).and_return(provider)
      allow(provider).to receive(:matches?).and_return(true)

      subject.embed_signature = true
      subject.encrypt = true
      result = subject.build
      expect(result).to be_valid
    end

    it 'includes the issuer' do
      subject.encrypt = false
      result = subject.build
      expect(result.issuer).to eql(issuer)
      expect(result.assertion.issuer).to eql(issuer)
    end

    it 'builds a response with a status code' do
      subject.status_code = Saml::Kit::Namespaces::REQUESTER_ERROR
      subject.status_message = 'Invalid message signature'
      result = subject.build
      expect(result.status_message).to eql('Invalid message signature')
    end

    it 'builds a response without an assertion' do
      subject.assertion = nil
      result = subject.build
      expect(result.assertion).not_to be_present
    end
  end

  describe '#to_xml' do
    it 'returns a proper response for the user' do
      travel_to 1.second.from_now
      allow(Saml::Kit.configuration).to receive(:entity_id).and_return(issuer)
      subject.destination = assertion_consumer_service_url
      subject.encrypt = false
      hash = Hash.from_xml(subject.to_xml)

      expect(hash['Response']['ID']).to be_present
      expect(hash['Response']['Version']).to eql('2.0')
      expect(hash['Response']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(hash['Response']['Destination']).to eql(assertion_consumer_service_url)
      expect(hash['Response']['InResponseTo']).to eql(request.id)
      expect(hash['Response']['Issuer']).to eql(issuer)
      expect(hash['Response']['Status']['StatusCode']['Value']).to eql('urn:oasis:names:tc:SAML:2.0:status:Success')

      expect(hash['Response']['Assertion']['ID']).to be_present
      expect(hash['Response']['Assertion']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(hash['Response']['Assertion']['Version']).to eql('2.0')
      expect(hash['Response']['Assertion']['Issuer']).to eql(issuer)

      expect(hash['Response']['Assertion']['Subject']['NameID']).to eql(user.name_id)
      expect(hash['Response']['Assertion']['Subject']['SubjectConfirmation']['Method']).to eql('urn:oasis:names:tc:SAML:2.0:cm:bearer')
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

      subject = described_class.new(user, request)
      hash = Hash.from_xml(subject.to_xml)
      expect(hash['Response']['Signature']).to be_nil
    end

    it 'generates an EncryptedAssertion' do
      subject.encrypt = true
      result = Hash.from_xml(subject.to_xml)
      expect(result['Response']['EncryptedAssertion']).to be_present
      encrypted_assertion = result['Response']['EncryptedAssertion']
      decrypted_assertion = Xml::Kit::Decryption.new(private_keys: configuration.private_keys(use: :encryption)).decrypt_hash(encrypted_assertion)
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
      subject.embed_signature = true
      result = Hash.from_xml(subject.to_xml)
      expect(result['Response']['Signature']).to be_present
      expect(result['Response']['EncryptedAssertion']).to be_present
    end

    it 'generates a signed response and assertion' do
      subject.encrypt = false
      subject.embed_signature = true
      result = Hash.from_xml(subject.to_xml)
      expect(result['Response']['Signature']).to be_present
      expect(result['Response']['Assertion']['Signature']).to be_present
    end

    it 'generates a signed response and signed and encrypted assertion' do
      subject.encrypt = true
      subject.embed_signature = true

      result = Saml::Kit::Response.new(subject.to_xml, configuration: configuration)
      expect(result).to be_signed
      expect(result.assertion).to be_signed
      expect(result.assertion).to be_encrypted
    end

    it 'generates an encrypted assertion' do
      subject.encrypt = true
      subject.embed_signature = false

      result = Saml::Kit::Response.new(subject.to_xml, configuration: configuration)
      expect(result).not_to be_signed
      expect(result.assertion).not_to be_signed
      expect(result.assertion).to be_encrypted
    end

    it 'excludes the nameid format when the request does not specify a nameid format in the nameid policy' do
      xml = <<-XML.strip_heredoc
        <samlp:AuthnRequest Version="2.0" ID="I_RzVGR.ktLi_wpo3IbsgwVJ2r8" IssueInstant="#{Time.now.iso8601}" Destination="#{FFaker::Internet.uri('https')}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
          <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{FFaker::Name.first_name}</saml:Issuer>
          <samlp:NameIDPolicy AllowCreate="true" />
          <samlp:RequestedAuthnContext Comparison="exact">
            <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
      XML
      authnrequest = Saml::Kit::AuthenticationRequest.new(xml)
      user = User.new(name_id: FFaker::Internet.email)
      result = Saml::Kit::Response.build(user, authnrequest)
      expect(result.assertion.name_id_format).to be_nil
    end
  end

  describe '.build' do
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.entity_id = issuer
        config.generate_key_pair_for(use: :signing)
        config.generate_key_pair_for(use: :signing)
        config.generate_key_pair_for(use: :signing)
      end
    end

    it 'signs the response with a specific certificate' do
      key_pair = configuration.key_pairs(use: :signing)[1]
      subject.embed_signature = true
      subject.sign_with(key_pair)

      result = subject.build

      expect(result).to be_signed
      expect(result.signature.certificate).to eql(key_pair.certificate)
    end
  end
end
