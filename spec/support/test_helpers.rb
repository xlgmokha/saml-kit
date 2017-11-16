module TestHelpers
  def query_params_from(url)
    Hash[uri_for(url).query.split("&").map { |x| x.split('=', 2) }]
  end

  def uri_for(url)
    URI.parse(url)
  end
end
