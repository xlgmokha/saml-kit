require_relative './principal'

RSpec.describe "Response" do
  let(:user) { Principal.new(id: SecureRandom.uuid, email: "hello@example.com") }
  let(:request) { Saml::Kit::AuthenticationRequest.build }

  it 'consumes a Response' do
    raw_xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_32594448-5d41-4e5b-87c5-ee32ef1f14f7" Version="2.0" IssueInstant="2017-12-23T18:13:58Z" Destination="" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_55236abc-636f-41d1-8c0d-81c5384786dd">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://www.example.com/metadata</Issuer>
  <Status>
    <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </Status>
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_843f14bc-51e9-40d3-9861-23e59ccc8427" IssueInstant="2017-12-23T18:13:58Z" Version="2.0">
    <Issuer>https://www.example.com/metadata</Issuer>
    <Subject>
      <NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">ed215a85-597f-4e74-a892-ac83c386190b</NameID>
      <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData InResponseTo="_55236abc-636f-41d1-8c0d-81c5384786dd" NotOnOrAfter="2017-12-23T21:13:58Z" Recipient=""/>
      </SubjectConfirmation>
    </Subject>
    <Conditions NotBefore="2017-12-23T18:13:58Z" NotOnOrAfter="2017-12-23T21:13:58Z">
      <AudienceRestriction>
        <Audience/>
      </AudienceRestriction>
    </Conditions>
    <AuthnStatement AuthnInstant="2017-12-23T18:13:58Z" SessionIndex="_843f14bc-51e9-40d3-9861-23e59ccc8427" SessionNotOnOrAfter="2017-12-23T21:13:58Z">
      <AuthnContext>
        <AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef>
      </AuthnContext>
    </AuthnStatement>
  </Assertion>
</Response>
    XML
    response = Saml::Kit::Response.new(raw_xml)
    expect(response.assertion.name_id).to eql('ed215a85-597f-4e74-a892-ac83c386190b')
    expect(response.issuer).to eql("https://www.example.com/metadata")
  end

  it 'builds a Response document' do
    response = Saml::Kit::Response.build(user, request) do |builder|
      builder.issuer = "blah"
    end

    expect(response.issuer).to eql("blah")
    expect(response.to_xml).to have_xpath("/samlp:Response/saml:Assertion/saml:Issuer[text()=\"blah\"]")
  end

  it 'generates a SAMLResponse' do
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
end

