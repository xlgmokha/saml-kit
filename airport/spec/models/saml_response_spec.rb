require 'rails_helper'

describe SamlResponse do
  describe ".parse" do
    subject { described_class }
    let(:raw_response) { IO.read('spec/fixtures/encoded_response.txt') }

<<-XML
<samlp:Response ID="_b0417350-9671-0135-55fc-20999b09e5e7" Version="2.0"
  IssueInstant="2017-10-18T20:34:39Z"
  Destination="http://localhost:3000/session"
  Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"
  InResponseTo="739102f5-faf9-4967-be74-ce45ecb4f753"
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">http://auth.dev/auth/metadata</Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_b0417400-9671-0135-55fc-20999b09e5e7"
    IssueInstant="2017-10-18T20:34:39Z" Version="2.0">
    <Issuer>http://auth.dev/auth/metadata</Issuer>
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">mokha@cisco.com</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData InResponseTo="739102f5-faf9-4967-be74-ce45ecb4f753" NotOnOrAfter="2017-10-18T20:37:39Z" Recipient="http://localhost:3000/session"></SubjectConfirmationData>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2017-10-18T20:34:34Z" NotOnOrAfter="2017-10-18T21:34:39Z">
      <AudienceRestriction><Audience>airport.dev</Audience></AudienceRestriction>
    </Conditions>
    <AttributeStatement>
      <Attribute Name="user_id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="user_id"><AttributeValue>760a54e2-31ba-4dfa-9303-fa6887270980</AttributeValue></Attribute>
      <Attribute Name="business_guid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="business_guid"><AttributeValue>e12dc2a6-6f18-4d11-8204-a98490896de8</AttributeValue></Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="2017-10-18T20:34:39Z" SessionIndex="_b0417400-9671-0135-55fc-20999b09e5e7"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement>
  </Assertion>
</samlp:Response>"
XML
    it 'decodes the response to the raw xml' do
      xml = subject.parse(raw_response).to_xml
      result = Hash.from_xml(xml)
      expect(result['Response']['ID']).to eql('_b0417350-9671-0135-55fc-20999b09e5e7')
      expect(result['Response']['Version']).to eql('2.0')
      expect(result['Response']['IssueInstant']).to eql('2017-10-18T20:34:39Z')
      expect(result['Response']['Destination']).to eql('http://localhost:3000/session')
      expect(result['Response']['Issuer']).to eql('http://auth.dev/auth/metadata')
      expect(result['Response']['Status']['StatusCode']['Value']).to eql('urn:oasis:names:tc:SAML:2.0:status:Success')
      expect(result['Response']['Assertion']['ID']).to eql('_b0417400-9671-0135-55fc-20999b09e5e7')
      expect(result['Response']['Assertion']['IssueInstant']).to eql('2017-10-18T20:34:39Z')
      expect(result['Response']['Assertion']['Issuer']).to eql('http://auth.dev/auth/metadata')
      expect(result['Response']['Assertion']['Subject']['NameID']).to eql('mokha@cisco.com')
      expect(result['Response']['Assertion']['Conditions']['NotBefore']).to eql('2017-10-18T20:34:34Z')
      expect(result['Response']['Assertion']['Conditions']['NotOnOrAfter']).to eql('2017-10-18T21:34:39Z')
      expect(result['Response']['Assertion']['Conditions']['AudienceRestriction']['Audience']).to eql('airport.dev')
      expect(result['Response']['Assertion']['AttributeStatement']['Attribute'][0]['Name']).to eql('user_id')
      expect(result['Response']['Assertion']['AttributeStatement']['Attribute'][0]['AttributeValue']).to eql('760a54e2-31ba-4dfa-9303-fa6887270980')
    end
  end
end
