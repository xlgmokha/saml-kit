module TestHelpers
  def query_params_from(url)
    Hash[query_for(url).split("&").map { |x| x.split('=', 2) }]
  end

  def uri_for(url)
    URI.parse(url)
  end

  def query_for(url)
    uri_for(url).query
  end
end
