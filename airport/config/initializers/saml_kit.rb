idp = nil
Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  idp = configuration.registry.register_url("#{ENV['AUTHENTICATION_HOST']}/metadata")
end
DEFAULT_IDP_ENTITY_ID=idp.entity_id
