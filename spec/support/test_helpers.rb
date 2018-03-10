# frozen_string_literal: true

module TestHelpers
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

RSpec.configure do |config|
  config.include TestHelpers
end
