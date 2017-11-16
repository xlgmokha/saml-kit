RSpec::Matchers.define :have_query_param do |key|
  match do |url|
    query_params_from(url)['SAMLRequest'].present?
  end
end
