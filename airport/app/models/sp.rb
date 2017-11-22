class Sp
  class << self
    def default(request)
      @sp ||= begin
        url_helpers = Rails.application.routes.url_helpers
        host = "#{request.protocol}#{request.host}:#{request.port}"
        builder = Saml::Kit::ServiceProviderMetadata::Builder.new
        builder.sign = false
        builder.add_assertion_consumer_service(url_helpers.consume_url(host: host), binding: :http_post)
        builder.add_single_logout_service(url_helpers.logout_url(host: host), binding: :http_post)
        builder.build
      end
    end
  end
end
