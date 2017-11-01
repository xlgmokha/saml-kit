require 'spec_helper'

RSpec.describe Saml::Kit::ServiceProviderMetadata do
  describe described_class::Builder do
    let(:entity_id) { FFaker::Movie.title }
    let(:acs_url) { "https://#{FFaker::Internet.domain_name}/acs" }

    <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  ID="_a94ad660-23cc-4491-8fe0-1429b7f5a6d8"
  entityID="https://service.dev/metadata">
  <md:SPSSODescriptor
    AuthnRequestsSigned="true"
    WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://service.dev/acs" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
    XML
    it 'builds the service provider metadata' do
      subject.entity_id = entity_id
      subject.acs_url = acs_url
      result = Hash.from_xml(subject.build.to_xml)

      expect(result['EntityDescriptor']['xmlns:md']).to eql("urn:oasis:names:tc:SAML:2.0:metadata")
      expect(result['EntityDescriptor']['ID']).to be_present
      expect(result['EntityDescriptor']['entityID']).to eql(entity_id)
      expect(result['EntityDescriptor']['SPSSODescriptor']['AuthnRequestsSigned']).to eql('true')
      expect(result['EntityDescriptor']['SPSSODescriptor']['WantAssertionsSigned']).to eql('true')
      expect(result['EntityDescriptor']['SPSSODescriptor']['protocolSupportEnumeration']).to eql('urn:oasis:names:tc:SAML:2.0:protocol')
      expect(result['EntityDescriptor']['SPSSODescriptor']['NameIDFormat']).to eql("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
      expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['Binding']).to eql("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
      expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['Location']).to eql(acs_url)
      expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['isDefault']).to eql('true')
      expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['index']).to eql('0')
      expect(result['EntityDescriptor']['Signature']).to be_present
      expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor']['use']).to eql("signing")
      expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor']['KeyInfo']['X509Data']['X509Certificate']).to eql(Saml::Kit.configuration.stripped_certificate)
    end
  end
end
