Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  Rails.configuration.x.idp_metadata =
    configuration.registry.register_url("#{ENV['AUTHENTICATION_HOST']}/metadata")
end
