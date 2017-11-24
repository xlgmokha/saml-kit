Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  configuration.registry = Metadatum
end
