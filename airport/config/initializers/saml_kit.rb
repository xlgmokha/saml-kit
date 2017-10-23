Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  configuration.acs_url = ENV['ACS_URL']
end
