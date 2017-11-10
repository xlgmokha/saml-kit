class MetadataController < ApplicationController
  skip_before_action :authenticate!

  def show
    render xml: to_xml
  end

  private

  def to_xml
    builder = Saml::Kit::ServiceProviderMetadata::Builder.new
    builder.sign = false
    builder.add_assertion_consumer_service(session_url, binding: :post)
    builder.to_xml
  end
end
