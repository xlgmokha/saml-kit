RSpec.describe "Metadata" do
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
    expect(metadata.to_xml(pretty: true)).to be_present
    expect(metadata.to_xml(pretty: true)).to have_xpath("//md:EntityDescriptor//md:IDPSSODescriptor")
    expect(metadata.to_xml(pretty: true)).to have_xpath("//md:EntityDescriptor//md:SPSSODescriptor")
  end
end
