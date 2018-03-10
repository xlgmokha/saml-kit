# frozen_string_literal: true

require 'uri'

RSpec::Matchers.define :have_query_param do |key|
  match do |url|
    query_params_from(url)[key].present?
  end

  def query_params_from(url)
    Hash[query_for(url).split('&').map { |xxx| xxx.split('=', 2) }]
  end

  def uri_for(url)
    URI.parse(url)
  end

  def query_for(url)
    uri_for(url).query
  end
end
