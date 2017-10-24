require 'spec_helper'

RSpec.describe Saml::Kit::IdentityProviderMetadata do
  describe described_class::Builder do
    subject { described_class.new }
    let(:email) { FFaker::Internet.email }
    let(:org_name) { FFaker::Movie.title }
    let(:url) { "https://#{FFaker::Internet.domain_name}" }
    let(:entity_id) { FFaker::Movie.title }

    it 'builds a proper metadata' do
      subject.contact_email = email
      subject.entity_id = entity_id
      subject.organization_name = org_name
      subject.organization_url = url
      subject.single_sign_on_location = "https://www.example.com/login"
      subject.single_logout_location = "https://www.example.com/logout"
      subject.attributes << "id"

      result = Hash.from_xml(subject.build.to_xml)

      expect(result['EntityDescriptor']['ID']).to be_present
      expect(result['EntityDescriptor']['entityID']).to eql(entity_id)
      expect(result['EntityDescriptor']['IDPSSODescriptor']['protocolSupportEnumeration']).to eql('urn:oasis:names:tc:SAML:2.0:protocol')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['NameIDFormat']).to eql('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleSignOnService']['Binding']).to eql('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleSignOnService']['Location']).to eql("https://www.example.com/login")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleLogoutService']['Binding']).to eql('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
      expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleLogoutService']['Location']).to eql("https://www.example.com/logout")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['Name']).to eql("id")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['FriendlyName']).to eql("id")
      expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['NameFormat']).to eql("urn:oasis:names:tc:SAML:2.0:attrname-format:uri")

      expect(result['EntityDescriptor']['Organization']['OrganizationName']).to eql(org_name)
      expect(result['EntityDescriptor']['Organization']['OrganizationDisplayName']).to eql(org_name)
      expect(result['EntityDescriptor']['Organization']['OrganizationURL']).to eql(url)
      expect(result['EntityDescriptor']['ContactPerson']['contactType']).to eql("technical")
      expect(result['EntityDescriptor']['ContactPerson']['Company']).to eql("mailto:#{email}")
    end
  end
end
