RSpec.describe "Identity Provider Metadata" do
  it 'produces identity provider metadata' do
    xml = Saml::Kit::Metadata.build_xml do |builder|
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
    end
    expect(xml).to be_present
    expect(xml).to have_xpath("//md:EntityDescriptor//md:IDPSSODescriptor")
    expect(xml).to_not have_xpath("//md:EntityDescriptor//md:SPSSODescriptor")
  end
end
