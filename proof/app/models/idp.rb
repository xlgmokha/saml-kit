class Idp
  class << self

    def default(request)
      @idp ||= begin
        host = "#{request.protocol}#{request.host}:#{request.port}"
        url_helpers = Rails.application.routes.url_helpers
        builder = Saml::Kit::IdentityProviderMetadata::Builder.new
        builder.sign = false
        builder.contact_email = 'hi@example.com'
        builder.organization_name = "Acme, Inc"
        builder.organization_url = url_helpers.root_url(host: host)
        builder.add_single_sign_on_service(url_helpers.new_session_url(host: host), binding: :post)
        builder.add_single_sign_on_service(url_helpers.new_session_url(host: host), binding: :http_redirect)
        builder.add_single_logout_service(url_helpers.logout_url(host: host), binding: :post)
        builder.name_id_formats = [
          Saml::Kit::Namespaces::EMAIL_ADDRESS,
          Saml::Kit::Namespaces::PERSISTENT,
          Saml::Kit::Namespaces::TRANSIENT,
        ]
        builder.attributes << :id
        builder.attributes << :email
        builder.attributes << :created_at
        builder.build
        end
    end
  end
end
