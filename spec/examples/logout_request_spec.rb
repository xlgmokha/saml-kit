require_relative './principal'

RSpec.describe "Logout Request" do
  let(:user) { Principal.new(id: SecureRandom.uuid, email: "hello@example.com") }

  it 'produces a SAMLRequest' do
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
      builder.build_service_provider do |x|
        x.add_assertion_consumer_service('https://www.example.com/consume', binding: :http_post)
        x.add_single_logout_service('https://www.example.com/logout', binding: :http_post)
      end
    end

    sp = Saml::Kit::IdentityProviderMetadata.new(xml)
    url, saml_params = sp.logout_request_for(user, binding: :http_post)
    expect(url).to eql("https://www.example.com/logout")
    expect(saml_params['SAMLRequest']).to be_present
  end
end
