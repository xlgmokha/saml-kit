class MetadataController < ApplicationController
  def show
    render xml: to_xml
  end

  private

  def to_xml
    builder = Saml::Kit::ServiceProviderMetadata::Builder.new
    builder.entity_id = "airport.dev"
    builder.acs_url = "http://localhost:4000/session"
    builder.to_xml
  end
end
