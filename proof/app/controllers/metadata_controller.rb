class MetadataController < ApplicationController
  def show
    render xml: to_xml
  end

  private

  def to_xml
    builder = Saml::Kit::IdentityProviderMetadata::Builder.new
    builder.sign = false
    builder.contact_email = 'hi@example.com'
    builder.organization_name = "Acme, Inc"
    builder.organization_url = root_url
    builder.add_single_sign_on_service(new_session_url, binding: :post)
    builder.add_single_sign_on_service(new_session_url, binding: :http_redirect)
    builder.add_single_logout_service(logout_url, binding: :post)
    builder.name_id_formats = [
      Saml::Kit::Namespaces::EMAIL_ADDRESS,
      Saml::Kit::Namespaces::PERSISTENT,
      Saml::Kit::Namespaces::TRANSIENT,
    ]
    builder.attributes << :id
    builder.attributes << :email
    builder.attributes << :created_at
    builder.build.to_xml
  end
end
