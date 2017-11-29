require 'spec_helper'

RSpec.describe Saml::Kit::ServiceProviderMetadata::Builder do
  let(:acs_url) { FFaker::Internet.http_url }
  let(:entity_id) { FFaker::Internet.uri("https") }

  it 'builds the service provider metadata' do
    subject.entity_id = entity_id
    subject.add_assertion_consumer_service(acs_url, binding: :http_post)
    subject.name_id_formats = [
      Saml::Kit::Namespaces::PERSISTENT,
      Saml::Kit::Namespaces::TRANSIENT,
      Saml::Kit::Namespaces::EMAIL_ADDRESS,
    ]
    result = Hash.from_xml(subject.build.to_xml)

    expect(result['EntityDescriptor']['xmlns']).to eql("urn:oasis:names:tc:SAML:2.0:metadata")
    expect(result['EntityDescriptor']['ID']).to be_present
    expect(result['EntityDescriptor']['entityID']).to eql(entity_id)
    expect(result['EntityDescriptor']['SPSSODescriptor']['AuthnRequestsSigned']).to eql('true')
    expect(result['EntityDescriptor']['SPSSODescriptor']['WantAssertionsSigned']).to eql('true')
    expect(result['EntityDescriptor']['SPSSODescriptor']['protocolSupportEnumeration']).to eql('urn:oasis:names:tc:SAML:2.0:protocol')
    expect(result['EntityDescriptor']['SPSSODescriptor']['NameIDFormat']).to match_array([
      Saml::Kit::Namespaces::PERSISTENT,
      Saml::Kit::Namespaces::TRANSIENT,
      Saml::Kit::Namespaces::EMAIL_ADDRESS,
    ])
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['Binding']).to eql("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['Location']).to eql(acs_url)
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['isDefault']).to eql('true')
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['index']).to eql('0')
    expect(result['EntityDescriptor']['Signature']).to be_present
    expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor'].map { |x| x['use'] }).to match_array(['signing', 'encryption'])
    expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor'].map { |x| x['KeyInfo']['X509Data']['X509Certificate'] }).to match_array([
      Saml::Kit.configuration.stripped_signing_certificate,
      Saml::Kit.configuration.stripped_encryption_certificate,
    ])
  end
end
