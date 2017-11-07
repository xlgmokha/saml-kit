DEFAULT_IDP_ENTITY_ID="#{ENV['AUTHENTICATION_HOST']}/metadata"
Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  configuration.registry.register_url(DEFAULT_IDP_ENTITY_ID)
end
