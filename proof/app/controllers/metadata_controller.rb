class MetadataController < ApplicationController
  def show
    render xml: to_xml
  end

  private

  def to_xml
    builder = Saml::Kit::IdentityProviderMetadata::Builder.new
    builder.contact_email = 'hi@example.com'
    builder.entity_id = metadata_url
    builder.organization_name = "Acme, Inc"
    builder.organization_url = root_url
    builder.single_sign_on_location = new_session_url
    builder.single_logout_location = session_url
    builder.attributes << "id"
    builder.attributes << "email"
    builder.attributes << "created_at"
    builder.build.to_xml
  end
end
