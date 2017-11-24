class MetadataController < ApplicationController
  force_ssl if: :ssl_configured?

  def show
    render xml: to_xml, content_type: "application/samlmetadata+xml"
  end

  private

  def to_xml
    Rails.cache.fetch(metadata_url, expires_in: 1.hour) do
      Sp.default(request).to_xml
    end
  end

  def ssl_configured?
    !Rails.env.development?
  end
end
