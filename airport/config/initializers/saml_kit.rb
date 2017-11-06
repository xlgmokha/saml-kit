Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  configuration.registry.register_url("#{ENV['AUTHENTICATION_HOST']}/metadata")
end
