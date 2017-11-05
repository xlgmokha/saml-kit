require 'spec_helper'

RSpec.describe Saml::Kit::Response do
  describe "#acs_url" do
    let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
    let(:user) { double(:user, uuid: SecureRandom.uuid, assertion_attributes_for: { }) }
    let(:request) { double(id: SecureRandom.uuid, acs_url: acs_url, issuer: FFaker::Movie.title) }
    subject { described_class::Builder.new(user, request).build }

    it 'returns the acs_url' do
      expect(subject.acs_url).to eql(acs_url)
    end
  end

  describe "#to_xml" do
    subject { described_class::Builder.new(user, request) }
    let(:user) { double(:user, uuid: SecureRandom.uuid, assertion_attributes_for: { email: email, created_at: Time.now.utc.iso8601 }) }
    let(:request) { double(id: SecureRandom.uuid, acs_url: acs_url, issuer: FFaker::Movie.title) }
    let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }
    let(:issuer) { FFaker::Movie.title }
    let(:email) { FFaker::Internet.email }

    <<-XML
<samlp:Response
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
  Version="2.0"
  IssueInstant="2014-07-17T01:01:48Z"
  Destination="http://sp.example.com/demo1/index.php?acs"
  InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"
    Version="2.0"
    IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
    XML
    it 'returns a proper response for the user' do
      travel_to 1.second.from_now
      allow(Saml::Kit.configuration).to receive(:issuer).and_return(issuer)
      result = subject.to_xml
      hash = Hash.from_xml(result)

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

      expect(hash['Response']['Assertion']['Subject']['NameID']).to eql(user.uuid)
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
  end

  describe ".parse" do
    subject { described_class }
    let(:raw_response) { IO.read('spec/fixtures/encoded_response.txt') }

    it 'decodes the response to the raw xml' do
      xml = subject.parse(raw_response).to_xml
      result = Hash.from_xml(xml)
      expect(result['Response']['ID']).to eql('_75358cd9-f357-4b2d-999f-f53382ba8263')
      expect(result['Response']['Version']).to eql('2.0')
      expect(result['Response']['IssueInstant']).to eql("2017-10-22T23:36:44Z")
      expect(result['Response']['Destination']).to eql('http://localhost:4000/session')
      expect(result['Response']['Issuer']).to eql('proof.dev')
      expect(result['Response']['Status']['StatusCode']['Value']).to eql('urn:oasis:names:tc:SAML:2.0:status:Success')
      expect(result['Response']['Assertion']['ID']).to eql("_78cacf76-243e-4509-9ace-d1985353b3fe")
      expect(result['Response']['Assertion']['IssueInstant']).to eql("2017-10-22T23:36:44Z")
      expect(result['Response']['Assertion']['Issuer']).to eql("proof.dev")
      expect(result['Response']['Assertion']['Subject']['NameID']).to eql("ea64c235-e18d-4b9a-8672-06ef84dabdec")
      expect(result['Response']['Assertion']['Conditions']['NotBefore']).to eql("2017-10-22T23:36:39Z")
      expect(result['Response']['Assertion']['Conditions']['NotOnOrAfter']).to eql("2017-10-23T02:36:44Z")
      expect(result['Response']['Assertion']['Conditions']['AudienceRestriction']['Audience']).to eql('airport.dev')
      expect(result['Response']['Assertion']['AttributeStatement']['Attribute'][0]['Name']).to eql('id')
      expect(result['Response']['Assertion']['AttributeStatement']['Attribute'][0]['AttributeValue']).to eql("ea64c235-e18d-4b9a-8672-06ef84dabdec")
    end
  end

  describe "#valid?" do
    let(:request) { instance_double(Saml::Kit::AuthenticationRequest, id: "_#{SecureRandom.uuid}", issuer: FFaker::Internet.http_url, acs_url: FFaker::Internet.http_url) }
    let(:user) { double(:user, uuid: SecureRandom.uuid, assertion_attributes_for: { id: SecureRandom.uuid }) }
    let(:builder) { described_class::Builder.new(user, request) }
    let(:registry) { instance_double(Saml::Kit::DefaultRegistry) }
    let(:metadata) { instance_double(Saml::Kit::IdentityProviderMetadata) }

    before :each do
      allow(Saml::Kit.configuration).to receive(:registry).and_return(registry)
    end

    it 'is valid' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      expect(builder.build).to be_valid
    end

    it 'is invalid when blank' do
      expect(described_class.new("")).to be_invalid
    end

    it 'is invalid if the document has been tampered with' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      name_id_format = Saml::Kit::Namespaces::PERSISTENT
      builder.name_id_format = name_id_format
      subject = described_class.new(builder.to_xml.gsub(name_id_format, Saml::Kit::Namespaces::EMAIL_ADDRESS))
      expect(subject).to_not be_valid
    end

    it 'is invalid when not a Response' do
      xml = Saml::Kit::IdentityProviderMetadata::Builder.new.to_xml
      expect(described_class.new(xml)).to be_invalid
    end

    it 'is invalid when the fingerprint of the certificate does not match the registered fingerprint' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(false)
      expect(described_class.new(builder.to_xml)).to be_invalid
    end

    it 'validates the schema of the response' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      xml = ::Builder::XmlMarkup.new
      id = SecureRandom.uuid
      options = { "xmlns:samlp" => Saml::Kit::Namespaces::PROTOCOL, ID: "_#{id}", }
      signature = Saml::Kit::Signature.new(id)
      xml.tag!("samlp:Response", options) do
        signature.template(xml)
        xml.Fake do
          xml.NotAllowed "Huh?"
        end
      end
      expect(described_class.new(signature.finalize(xml))).to be_invalid
    end

    it 'validates the version' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      builder.version = "1.1"
      expect(described_class.new(builder.to_xml)).to be_invalid
    end

    it 'validates the id' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      builder.id = nil
      expect(described_class.new(builder.to_xml)).to_not be_valid
    end

    it 'validates the status code' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      builder.status_code = Saml::Kit::Namespaces::REQUESTER_ERROR
      expect(described_class.new(builder.to_xml)).to_not be_valid
    end

    it 'validates the InResponseTo' do
      allow(registry).to receive(:metadata_for).and_return(metadata)
      allow(metadata).to receive(:matches?).and_return(true)
      expect(described_class.new(builder.to_xml, request_id: SecureRandom.uuid)).to_not be_valid
    end
  end
end
