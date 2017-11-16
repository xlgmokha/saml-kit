RSpec::Matchers.define :have_query_param do |key|
  match do |url|
    query_params(url)['SAMLRequest'].present?
  end

  def query_params(url)
    Hash[uri_for(url).query.split("&").map { |x| x.split('=', 2) }]
  end

  def uri_for(url)
    URI.parse(url)
  end
end
