# frozen_string_literal: true

RSpec.describe Saml::Kit::Builders::IdentityProviderMetadata do
  subject { described_class.new(configuration: configuration) }

  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.generate_key_pair_for(use: :signing)
      config.generate_key_pair_for(use: :encryption)
    end
  end
  let(:email) { FFaker::Internet.email }
  let(:org_name) { FFaker::Movie.title }
  let(:url) { FFaker::Internet.uri('https') }
  let(:entity_id) { FFaker::Movie.title }

  it 'builds a proper metadata' do
    subject.contact_email = email
    subject.entity_id = entity_id
    subject.organization_name = org_name
    subject.organization_url = url
    subject.name_id_formats = [
      Saml::Kit::Namespaces::PERSISTENT,
      Saml::Kit::Namespaces::TRANSIENT,
      Saml::Kit::Namespaces::EMAIL_ADDRESS,
    ]
    subject.add_single_sign_on_service('https://www.example.com/login', binding: :http_redirect)
    subject.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
    subject.attributes << 'id'

    result = Hash.from_xml(subject.build.to_xml)

    expect(result['EntityDescriptor']['ID']).to be_present
    expect(result['EntityDescriptor']['entityID']).to eql(entity_id)
    expect(result['EntityDescriptor']['IDPSSODescriptor']['protocolSupportEnumeration']).to eql(Saml::Kit::Namespaces::PROTOCOL)
    expect(result['EntityDescriptor']['IDPSSODescriptor']['WantAuthnRequestsSigned']).to eql('true')
    expect(result['EntityDescriptor']['IDPSSODescriptor']['NameIDFormat']).to match_array([
      Saml::Kit::Namespaces::PERSISTENT,
      Saml::Kit::Namespaces::TRANSIENT,
      Saml::Kit::Namespaces::EMAIL_ADDRESS,
    ])
    expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleSignOnService']['Binding']).to eql(Saml::Kit::Bindings::HTTP_REDIRECT)
    expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleSignOnService']['Location']).to eql('https://www.example.com/login')
    expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleLogoutService']['Binding']).to eql(Saml::Kit::Bindings::HTTP_POST)
    expect(result['EntityDescriptor']['IDPSSODescriptor']['SingleLogoutService']['Location']).to eql('https://www.example.com/logout')
    expect(result['EntityDescriptor']['IDPSSODescriptor']['Attribute']['Name']).to eql('id')
    certificates = result['EntityDescriptor']['IDPSSODescriptor']['KeyDescriptor'].map { |x| x['KeyInfo']['X509Data']['X509Certificate'] }
    expected_certificates = configuration.certificates.map(&:stripped)
    expect(certificates).to match_array(expected_certificates)
    expect(result['EntityDescriptor']['Organization']['OrganizationName']).to eql(org_name)
    expect(result['EntityDescriptor']['Organization']['OrganizationDisplayName']).to eql(org_name)
    expect(result['EntityDescriptor']['Organization']['OrganizationURL']).to eql(url)
    expect(result['EntityDescriptor']['ContactPerson']['contactType']).to eql('technical')
    expect(result['EntityDescriptor']['ContactPerson']['Company']).to eql("mailto:#{email}")
  end
end
