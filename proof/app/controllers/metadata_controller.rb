class MetadataController < ApplicationController
  def show
    render xml: to_xml
  end

  private

  def to_xml
    Rails.cache.fetch(metadata_url, expires_in: 1.hour) do
      Idp.default(request).to_xml
    end
  end
end
