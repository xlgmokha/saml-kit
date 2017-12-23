RSpec.describe "Service Provider Metadata" do
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
