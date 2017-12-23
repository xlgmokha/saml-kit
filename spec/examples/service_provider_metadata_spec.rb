RSpec.describe "Service Provider Metadata" do
  it 'consumes service provider_metadata' do
    raw_xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="myEntityId" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
  </SPSSODescriptor>
</EntityDescriptor>
    XML

    metadata = Saml::Kit::ServiceProviderMetadata.new(raw_xml)
    expect(metadata.entity_id).to eql('myEntityId')
    expect(metadata.name_id_formats).to match_array([Saml::Kit::Namespaces::PERSISTENT])
  end

  it 'produces service provider metadata' do
    metadata = Saml::Kit::Metadata.build do |builder|
      builder.contact_email = 'hi@example.com'
      builder.organization_name = "Acme, Inc"
      builder.organization_url = 'https://www.example.com'
      builder.build_service_provider do |x|
        x.add_assertion_consumer_service('https://www.example.com/consume', binding: :http_post)
        x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
      end
    end
    xml = metadata.to_xml(pretty: true)
    expect(xml).to be_present
    expect(xml).to_not have_xpath("//md:EntityDescriptor//md:IDPSSODescriptor")
    expect(xml).to have_xpath("//md:EntityDescriptor//md:SPSSODescriptor")
  end
end
