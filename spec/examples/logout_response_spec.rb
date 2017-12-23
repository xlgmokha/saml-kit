require_relative './user'

RSpec.describe "Logout Response" do
  let(:user) { User.new(id: SecureRandom.uuid, email: "hello@example.com") }

  it 'generates a logout response' do
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

    idp = Saml::Kit::IdentityProviderMetadata.new(xml)
    url, saml_params = idp.logout_request_for(user, binding: :http_post)
    uri = URI.parse("#{url}?#{saml_params.map { |(x, y)| "#{x}=#{y}" }.join('&')}")

    raw_params = Hash[uri.query.split("&amp;").map { |x| x.split("=", 2) }].symbolize_keys

    binding = idp.single_logout_service_for(binding: :http_post)
    saml_request = binding.deserialize(raw_params)
    sp = Saml::Kit::ServiceProviderMetadata.new(xml)
    allow(saml_request).to receive(:provider).and_return(sp)
    url, saml_params = saml_request.response_for(binding: :http_post)
    expect(url).to eql("https://www.example.com/logout")
    expect(saml_params['SAMLResponse']).to be_present
  end
end
