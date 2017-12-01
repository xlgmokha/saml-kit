require 'spec_helper'

RSpec.describe Saml::Kit::Response do
  describe "#valid?" do
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: "_#{SecureRandom.uuid}", issuer: FFaker::Internet.http_url, assertion_consumer_service_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, provider: nil, signed?: true, trusted?: true) }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: { id: SecureRandom.uuid }) }
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::IdentityProviderMetadata) }
    subject { described_class.build(user, request) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(request.issuer)
    end

    it 'is valid' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      expect(subject).to be_valid
    end

    it 'is invalid when blank' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = described_class.new("")
      expect(subject).to be_invalid
      expect(subject.errors[:content]).to be_present
    end

    it 'is invalid if the document has been tampered with' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      status_code = FFaker::Movie.title
      xml = described_class.build(user, request) do |builder|
        builder.status_code = status_code
      end.to_xml.gsub(status_code, "TAMPERED")
      subject = described_class.new(xml)
      expect(subject).to be_invalid
    end

    it 'is invalid when not a Response' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      subject = described_class.new(Saml::Kit::IdentityProviderMetadata.build.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(false)
      expect(subject).to be_invalid
      expect(subject.errors[:fingerprint]).to be_present
    end

    it 'validates the schema of the response' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      id = SecureRandom.uuid
      signed_xml = Saml::Kit::Signature.sign(sign: true) do |xml, signature|
        xml.tag! "samlp:Response", "xmlns:samlp" => Saml::Kit::Namespaces::PROTOCOL, ID: "_#{id}" do
          signature.template(id)
          xml.Fake do
            xml.NotAllowed "Huh?"
          end
        end
      end
      subject = described_class.new(signed_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to be_present
    end

    it 'validates the version' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.build(user, request) do |builder|
        builder.version = "1.1"
      end
      expect(subject).to be_invalid
      expect(subject.errors[:version]).to be_present
    end

    it 'validates the id' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.build(user, request) do |builder|
        builder.id = nil
      end
      expect(subject).to be_invalid
      expect(subject.errors[:id]).to be_present
    end

    it 'validates the status code' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.build(user, request) do |builder|
        builder.status_code = Saml::Kit::Namespaces::REQUESTER_ERROR
      end
      expect(subject).to be_invalid
      expect(subject.errors[:status_code]).to be_present
    end

    it 'validates the InResponseTo' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      xml = described_class.build(user, request).to_xml
      subject = described_class.new(xml, request_id: SecureRandom.uuid)

      expect(subject).to be_invalid
      expect(subject.errors[:in_response_to]).to be_present
    end

    it 'is invalid after a valid session window' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      subject = described_class.build(user, request)
      travel_to Saml::Kit.configuration.session_timeout.from_now + 5.seconds
      expect(subject).to_not be_valid
      expect(subject.errors[:base]).to be_present
    end

    it 'is invalid before the valid session window' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      subject = described_class.build(user, request)
      travel_to 5.seconds.ago
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to be_present
    end

    it 'is invalid when the audience does not match the expected issuer' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      allow(Saml::Kit.configuration).to receive(:issuer).and_return(FFaker::Internet.uri("https"))
      allow(request).to receive(:issuer).and_return(FFaker::Internet.uri("https"))

      expect(subject).to be_invalid
      expect(subject.errors[:audience]).to be_present
    end

    it 'is invalid' do
      now = Time.now.utc
      destination = FFaker::Internet.uri("https")
      raw_xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{SecureRandom.uuid}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{destination}" Consent="#{Saml::Kit::Namespaces::UNSPECIFIED}" InResponseTo="#{request.id}">
  <Issuer xmlns="#{Saml::Kit::Namespaces::ASSERTION}">#{request.issuer}</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="#{Saml::Kit::Namespaces::RESPONDER_ERROR}"/>
  </samlp:Status>
</samlp:Response>
      XML

      allow(registry).to receive(:metadata_for).with(request.issuer).and_return(metadata)
      subject = described_class.new(raw_xml)
      expect(subject).to be_invalid
    end
  end

  describe "#signed?" do
    let(:now) { Time.now.utc }
    let(:id) { SecureRandom.uuid }
    let(:url) { FFaker::Internet.uri("https") }

    it 'returns true when the Assertion is signed' do
      xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
  <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" IssueInstant="#{now.iso8601}" Version="2.0">
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_#{id}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue></ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue></ds:SignatureValue>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate></ds:X509Certificate>
        </ds:X509Data>
      </KeyInfo>
    </ds:Signature>
  </Assertion>
</samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject).to be_signed
    end

    it 'returns true when the Response is signed' do
      xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_#{id}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data>
        <ds:X509Certificate></ds:X509Certificate>
      </ds:X509Data>
    </KeyInfo>
  </ds:Signature>
  <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
</samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject).to be_signed
    end

    it 'returns false when there is no signature' do
      xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
  <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
</samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject).to_not be_signed
    end
  end

  describe "#certificate" do
    let(:now) { Time.now.utc }
    let(:id) { SecureRandom.uuid }
    let(:url) { FFaker::Internet.uri("https") }
    let(:certificate) { FFaker::Movie.title }

    it 'returns the certificate when the Assertion is signed' do
      xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
  <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" IssueInstant="#{now.iso8601}" Version="2.0">
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_#{id}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue></ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue></ds:SignatureValue>
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>#{certificate}</ds:X509Certificate>
        </ds:X509Data>
      </KeyInfo>
    </ds:Signature>
  </Assertion>
</samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject.certificate).to eql(certificate)
    end

    it 'returns the certificate when the Response is signed' do
      xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_#{id}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <ds:X509Data>
        <ds:X509Certificate>#{certificate}</ds:X509Certificate>
      </ds:X509Data>
    </KeyInfo>
  </ds:Signature>
  <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
</samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject.certificate).to eql(certificate)
    end

    it 'returns nil when there is no signature' do
      xml = <<-XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_#{SecureRandom.uuid}">
  <Assertion xmlns="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" IssueInstant="#{now.iso8601}" Version="2.0"></Assertion>
</samlp:Response>
      XML
      subject = described_class.new(xml)
      expect(subject.certificate).to be_nil
    end
  end

  describe "encrypted assertion" do
    let(:id) { SecureRandom.uuid }
    let(:now) { Time.now.utc }
    let(:assertion_consumer_service_url) { FFaker::Internet.uri("https") }
    let(:password) { FFaker::Movie.title }
    let(:assertion) do
      FFaker::Movie.title
      <<-XML
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_11d39a7f-1b86-43ed-90d7-68090a857ca8" IssueInstant="2017-11-23T04:33:58Z" Version="2.0">
 <Issuer>#{FFaker::Internet.uri("https")}</Issuer>
 <Subject>
   <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">fdddf7ad-c4a4-443c-b96d-c953913b7b4e</NameID>
   <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
     <SubjectConfirmationData InResponseTo="cc8c4131-9336-4d1a-82f2-4ad92abeee22" NotOnOrAfter="2017-11-23T07:33:58Z" Recipient="https://westyundt.ca/acs"/>
   </SubjectConfirmation>
 </Subject>
 <Conditions NotBefore="2017-11-23T04:33:58Z" NotOnOrAfter="2017-11-23T07:33:58Z">
   <AudienceRestriction>
     <Audience>American Wolves</Audience>
   </AudienceRestriction>
 </Conditions>
 <AuthnStatement AuthnInstant="2017-11-23T04:33:58Z" SessionIndex="_11d39a7f-1b86-43ed-90d7-68090a857ca8" SessionNotOnOrAfter="2017-11-23T07:33:58Z">
   <AuthnContext>
     <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
   </AuthnContext>
 </AuthnStatement>
 <AttributeStatement>
   <Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="email">
     <AttributeValue>sidney_bayer@nienowemmerich.com</AttributeValue>
   </Attribute>
   <Attribute Name="created_at" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="created_at">
     <AttributeValue>2017-11-23T04:33:58Z</AttributeValue>
   </Attribute>
 </AttributeStatement>
</Assertion>
XML
    end

    it 'parses the encrypted assertion' do
      certificate_pem, private_key_pem = Saml::Kit::SelfSignedCertificate.new(password).create
      public_key = OpenSSL::X509::Certificate.new(certificate_pem).public_key
      private_key = OpenSSL::PKey::RSA.new(private_key_pem, password)

      allow(Saml::Kit.configuration).to receive(:encryption_private_key).and_return(private_key)

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      key = cipher.random_key
      iv = cipher.random_iv
      encrypted = cipher.update(assertion) + cipher.final

      xml = <<-XML
<samlp:Response xmlns:samlp="#{Saml::Kit::Namespaces::PROTOCOL}" xmlns:saml="#{Saml::Kit::Namespaces::ASSERTION}" ID="_#{id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{assertion_consumer_service_url}" InResponseTo="_#{SecureRandom.uuid}">
  <saml:Issuer>#{FFaker::Internet.uri("https")}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="#{Saml::Kit::Namespaces::SUCCESS}"/>
  </samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
    <dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
      <xenc:EncryptedKey>
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
        <xenc:CipherData>
          <xenc:CipherValue>#{Base64.encode64(public_key.public_encrypt(key))}</xenc:CipherValue>
        </xenc:CipherData>
      </xenc:EncryptedKey>
    </dsig:KeyInfo>
    <xenc:CipherData>
      <xenc:CipherValue>#{Base64.encode64(iv + encrypted)}</xenc:CipherValue>
    </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>
XML

      subject = described_class.new(xml)
      expect(subject).to be_encrypted
      expect(subject.attributes).to be_present
    end
  end
end
