Saml::Kit.configure do |configuration|
  configuration.issuer = ENV['ISSUER']
  Rails.configuration.x.idp_metadata = configuration.registry.register_url("#{ENV['IDP_METADATA_URL']}", verify_ssl: Rails.env.production?)
end
