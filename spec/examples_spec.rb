RSpec.describe "Examples" do
  class User
    attr_reader :id, :email

    def initialize(id:, email:)
      @id = id
      @email = email
    end

    def name_id_for(name_id_format)
      Saml::Kit::Namespaces::PERSISTENT == name_id_format ? id : email
    end

    def assertion_attributes_for(request)
      request.trusted? ? { access_token: SecureRandom.uuid } : {}
    end
  end

  let(:user) { User.new(id: SecureRandom.uuid, email: "hello@example.com") }

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

  it 'produces an authentication request' do
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
    url, saml_params = idp.login_request_for(binding: :http_post)

    expect(url).to eql("https://www.example.com/login")
    expect(saml_params['SAMLRequest']).to be_present
  end

  it 'produces a logout request' do
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

  it 'generates a response' do
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
    url, saml_params = idp.login_request_for(binding: :http_post)
    uri = URI.parse("#{url}?#{saml_params.map { |(x, y)| "#{x}=#{y}" }.join('&')}")

    sp = Saml::Kit::ServiceProviderMetadata.new(xml)

    binding = idp.single_sign_on_service_for(binding: :http_post)
    raw_params = Hash[uri.query.split("&amp;").map { |x| x.split("=", 2) }].symbolize_keys
    saml_request = binding.deserialize(raw_params)
    allow(saml_request).to receive(:provider).and_return(sp)

    url, saml_params = saml_request.response_for(user, binding: :http_post)
    expect(url).to eql("https://www.example.com/consume")
    expect(saml_params['SAMLResponse']).to be_present
  end

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
