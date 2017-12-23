RSpec.describe "Metadata" do
  it 'consumes metadata' do
    raw_xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="https://www.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_50643868-c737-40c8-a30d-b5dc7f3c69d9">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/login"/>
  </IDPSSODescriptor>
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://www.example.com/consume" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>
    XML

    metadata = Saml::Kit::Metadata.from(raw_xml)
    expect(metadata.entity_id).to eql('https://www.example.com/metadata')
  end

  it 'produces metadata for a service provider and identity provider' do
    metadata = Saml::Kit::Metadata.build do |builder|
      builder.contact_email = 'hi@example.com'
      builder.organization_name = "Acme, Inc"
      builder.organization_url = 'https://www.example.com'
      builder.build_identity_provider do |x|
        x.add_single_sign_on_service('https://www.example.com/login', binding: :http_post)
        x.add_single_sign_on_service('https://www.example.com/login', binding: :http_redirect)
        x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
        x.name_id_formats = [ Saml::Kit::Namespaces::EMAIL_ADDRESS ]
        x.attributes << :id
        x.attributes << :email
      end
      builder.build_service_provider do |x|
        x.add_assertion_consumer_service('https://www.example.com/consume', binding: :http_post)
        x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
      end
    end
    xml = metadata.to_xml(pretty: true)
    expect(xml).to be_present
    expect(xml).to have_xpath("//md:EntityDescriptor//md:IDPSSODescriptor")
    expect(xml).to have_xpath("//md:EntityDescriptor//md:SPSSODescriptor")
  end
end
