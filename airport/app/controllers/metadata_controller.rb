class MetadataController < ApplicationController
  def show
    render xml: to_xml
  end

  private

  def to_xml
    builder = Saml::Kit::ServiceProviderMetadata::Builder.new
    builder.add_assertion_consumer_service(session_url, binding: :post)
    builder.to_xml
  end
end
