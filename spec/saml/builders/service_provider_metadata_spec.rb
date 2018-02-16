RSpec.describe Saml::Kit::Builders::ServiceProviderMetadata do
  subject { described_class.new(configuration: configuration) }

  let(:configuration) do
    Saml::Kit::Configuration.new do |config|
      config.generate_key_pair_for(use: :signing)
      config.generate_key_pair_for(use: :encryption)
    end
  end
  let(:assertion_consumer_service_url) { FFaker::Internet.http_url }
  let(:email) { FFaker::Internet.email }
  let(:org_name) { FFaker::Movie.title }
  let(:url) { FFaker::Internet.uri('https') }
  let(:entity_id) { FFaker::Internet.uri('https') }

  it 'builds the service provider metadata' do
    subject.contact_email = email
    subject.entity_id = entity_id
    subject.organization_name = org_name
    subject.organization_url = url
    subject.add_assertion_consumer_service(assertion_consumer_service_url, binding: :http_post)
    subject.name_id_formats = [
      Saml::Kit::Namespaces::PERSISTENT,
      Saml::Kit::Namespaces::TRANSIENT,
      Saml::Kit::Namespaces::EMAIL_ADDRESS,
    ]
    result = Hash.from_xml(subject.build.to_xml)

    expect(result['EntityDescriptor']['xmlns']).to eql('urn:oasis:names:tc:SAML:2.0:metadata')
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
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['Binding']).to eql('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['Location']).to eql(assertion_consumer_service_url)
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['isDefault']).to eql('true')
    expect(result['EntityDescriptor']['SPSSODescriptor']['AssertionConsumerService']['index']).to eql('0')
    expect(result['EntityDescriptor']['Signature']).to be_present
    expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor'].map { |x| x['use'] }).to match_array(%w[signing encryption])
    expected_certificates = configuration.certificates.map(&:stripped)
    expect(result['EntityDescriptor']['SPSSODescriptor']['KeyDescriptor'].map { |x| x['KeyInfo']['X509Data']['X509Certificate'] }).to match_array(expected_certificates)
    expect(result['EntityDescriptor']['Organization']['OrganizationName']).to eql(org_name)
    expect(result['EntityDescriptor']['Organization']['OrganizationDisplayName']).to eql(org_name)
    expect(result['EntityDescriptor']['Organization']['OrganizationURL']).to eql(url)
    expect(result['EntityDescriptor']['ContactPerson']['contactType']).to eql('technical')
    expect(result['EntityDescriptor']['ContactPerson']['Company']).to eql("mailto:#{email}")
  end
end
