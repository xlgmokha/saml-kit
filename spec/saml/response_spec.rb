require 'spec_helper'

RSpec.describe Saml::Kit::Response do
  describe "#destination" do
    let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: []) }
    subject { described_class::Builder.new(user, request).build }

    describe "when the request is signed and trusted" do
      let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: SecureRandom.uuid, acs_url: acs_url, issuer: FFaker::Movie.title, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: nil, signed?: true, trusted?: true) }

      it 'returns the ACS embedded in the request' do
        expect(subject.destination).to eql(acs_url)
      end
    end

    describe "when the request is not trusted" do
      let(:registered_acs_url) { FFaker::Internet.uri("https") }
      let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: SecureRandom.uuid, acs_url: acs_url, issuer: FFaker::Movie.title, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: provider, signed?: true, trusted?: false) }
      let(:provider) { instance_double(Saml::Kit::ServiceProviderMetadata, want_assertions_signed: false) }

      it 'returns the registered ACS embedded in the metadata' do
        allow(provider).to receive(:assertion_consumer_service_for).and_return(double(location: registered_acs_url))
        expect(subject.destination).to eql(registered_acs_url)
      end
    end
  end

  describe "#to_xml" do
    subject { described_class::Builder.new(user, request) }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: { email: email, created_at: Time.now.utc.iso8601 }) }
    let(:request) { double(id: SecureRandom.uuid, acs_url: acs_url, issuer: FFaker::Movie.title, name_id_format: Saml::Kit::Namespaces::EMAIL_ADDRESS, provider: nil, trusted?: true, signed?: true) }
    let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
    let(:issuer) { FFaker::Movie.title }
    let(:email) { FFaker::Internet.email }

    it 'returns a proper response for the user' do
      travel_to 1.second.from_now
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
      hash = Hash.from_xml(subject.to_xml)

      expect(hash['Response']['ID']).to be_present
      expect(hash['Response']['Version']).to eql('2.0')
      expect(hash['Response']['IssueInstant']).to eql(Time.now.utc.iso8601)
      expect(hash['Response']['Destination']).to eql(acs_url)
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
      expect(hash['Response']['Assertion']['Subject']['SubjectConfirmation']['SubjectConfirmationData']['Recipient']).to eql(acs_url)
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
      builder = Saml::Kit::ServiceProviderMetadata::Builder.new
      builder.want_assertions_signed = false
      metadata = builder.build
      allow(request).to receive(:provider).and_return(metadata)

      hash = Hash.from_xml(subject.to_xml)
      expect(hash['Response']['Signature']).to be_nil
    end
  end

  describe "#valid?" do
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: "_#{SecureRandom.uuid}", issuer: FFaker::Internet.http_url, acs_url: FFaker::Internet.http_url, name_id_format: Saml::Kit::Namespaces::PERSISTENT, provider: nil, signed?: true, trusted?: true) }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: { id: SecureRandom.uuid }) }
    let(:builder) { described_class::Builder.new(user, request) }
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::IdentityProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(request.issuer)
    end

    it 'is valid' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      expect(builder.build).to be_valid
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
      builder.status_code = status_code
      subject = described_class.new(builder.to_xml.gsub(status_code, "TAMPERED"))
      expect(subject).to be_invalid
    end

    it 'is invalid when not a Response' do
      allow(registry).to receive(:metadata_for).and_return(nil)
      xml = Saml::Kit::IdentityProviderMetadata::Builder.new.to_xml
      subject = described_class.new(xml)
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to include(subject.error_message(:invalid))
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(false)
      subject = described_class.new(builder.to_xml)
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
      builder.version = "1.1"
      subject = described_class.new(builder.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:version]).to be_present
    end

    it 'validates the id' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      builder.id = nil
      subject = described_class.new(builder.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:id]).to be_present
    end

    it 'validates the status code' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      builder.status_code = Saml::Kit::Namespaces::REQUESTER_ERROR
      subject = described_class.new(builder.to_xml)
      expect(subject).to be_invalid
      expect(subject.errors[:status_code]).to be_present
    end

    it 'validates the InResponseTo' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      subject = described_class.new(builder.to_xml, request_id: SecureRandom.uuid)
      expect(subject).to be_invalid
      expect(subject.errors[:in_response_to]).to be_present
    end

    it 'is invalid after a valid session window' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      subject = described_class.new(builder.to_xml)
      travel_to Saml::Kit.configuration.session_timeout.from_now + 5.seconds
      expect(subject).to_not be_valid
      expect(subject.errors[:base]).to be_present
    end

    it 'is invalid before the valid session window' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      subject = described_class.new(builder.to_xml)
      travel_to 5.seconds.ago
      expect(subject).to be_invalid
      expect(subject.errors[:base]).to be_present
    end

    it 'is invalid when the audience does not match the expected issuer' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)

      allow(Saml::Kit.configuration).to receive(:issuer).and_return(FFaker::Internet.http_url)
      allow(request).to receive(:issuer).and_return(FFaker::Internet.http_url)
      subject = described_class.new(builder.to_xml)

      expect(subject).to be_invalid
      expect(subject.errors[:audience]).to be_present
    end

    it 'is invalid' do
      now = Time.now.utc
      destination = FFaker::Internet.http_url
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

  describe described_class::Builder do
    subject { described_class.new(user, request) }
    let(:user) { double(:user, name_id_for: SecureRandom.uuid, assertion_attributes_for: []) }
    let(:request) { double(:request, id: SecureRandom.uuid, acs_url: FFaker::Internet.http_url, provider: nil, name_id_format: Saml::Kit::Namespaces::PERSISTENT, issuer: FFaker::Internet.http_url, signed?: true, trusted?: true) }

    describe "#build" do
      it 'builds a response with the request_id' do
        expect(subject.build.request_id).to eql(request.id)
      end
    end

    describe "#to_xml" do
      xit 'generates an EncryptedAssertion' do
        subject.encrypt = true
        result = Hash.from_xml(subject.to_xml)
        expect(result['Response']['EncryptedAssertion']).to be_present
      end
    end
  end
end
