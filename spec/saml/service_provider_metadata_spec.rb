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
      subject.add_assertion_consumer_service(acs_url, binding: :post)
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
      expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor']['KeyInfo']['X509Data']['X509Certificate']).to eql(Saml::Kit.configuration.stripped_signing_certificate)
    end
  end

  describe described_class do
    let(:entity_id) { FFaker::Movie.title }
    let(:acs_post_url) { "https://#{FFaker::Internet.domain_name}/post" }
    let(:acs_redirect_url) { "https://#{FFaker::Internet.domain_name}/redirect" }
    let(:logout_post_url) { "https://#{FFaker::Internet.domain_name}/post" }
    let(:logout_redirect_url) { "https://#{FFaker::Internet.domain_name}/redirect" }
    let(:builder) { described_class::Builder.new }
    subject do
      builder.entity_id = entity_id
      builder.add_assertion_consumer_service(acs_post_url, binding: :post)
      builder.add_assertion_consumer_service(acs_redirect_url, binding: :http_redirect)
      builder.add_single_logout_service(logout_post_url, binding: :post)
      builder.add_single_logout_service(logout_redirect_url, binding: :http_redirect)
      builder.build
    end

    it 'returns each of the certificates' do
      expected_sha256 = OpenSSL::Digest::SHA256.new.hexdigest(Saml::Kit.configuration.signing_x509.to_der)
      expect(subject.certificates).to match_array([
        {
          fingerprint: expected_sha256.upcase.scan(/../).join(":"),
          use: "signing",
          text: Saml::Kit.configuration.stripped_signing_certificate
        }
      ])
    end

    it 'returns each acs url and binding' do
      expect(subject.assertion_consumer_services).to match_array([
        { location: acs_post_url, binding: Saml::Kit::Namespaces::Bindings::POST },
        { location: acs_redirect_url, binding: Saml::Kit::Namespaces::Bindings::HTTP_REDIRECT },
      ])
    end

    it 'returns each logout url and binding' do
      expect(subject.single_logout_services).to match_array([
        { location: logout_post_url, binding: Saml::Kit::Namespaces::Bindings::POST },
        { location: logout_redirect_url, binding: Saml::Kit::Namespaces::Bindings::HTTP_REDIRECT },
      ])
    end

    it 'returns each of the nameid formats' do
      expect(subject.name_id_formats).to match_array([
        Saml::Kit::Namespaces::Formats::NameId::PERSISTENT
      ])
    end
  end
end
