module Saml
  module Kit
    # This class can be used to parse a LogoutRequest SAML document.
    #
    #   document = Saml::Kit::LogoutRequest.new(raw_xml)
    #
    # It can also be used to generate a new LogoutRequest.
    #
    #   document = Saml::Kit::LogoutRequest.build do |builder|
    #     builder.issuer = "issuer"
    #   end
    #
    #   puts document.to_xml(pretty: true)
    #
    # See {Saml::Kit::Builders::LogoutRequest} for a list of available settings.
    #
    # This class can also be used to generate the correspondong LogoutResponse for a LogoutRequest.
    #
    #   document = Saml::Kit::LogoutRequest.new(raw_xml)
    #   url, saml_params = document.response_for(binding: :http_post)
    #
    # See {#response_for} for more information.
    #
    # {include:file:spec/examples/logout_request_spec.rb}
    class LogoutRequest < Document
      include Requestable
      validates_presence_of :single_logout_service, if: :expected_type?

      # A new instance of LogoutRequest
      #
      # @param xml [String] The raw xml string.
      # @param configuration [Saml::Kit::Configuration] the configuration to use.
      def initialize(xml, configuration: Saml::Kit.configuration)
        super(xml, name: "LogoutRequest", configuration: configuration)
      end

      # Returns the NameID value.
      def name_id
        to_h[name]['NameID']
      end

      # Generates a Serialized LogoutResponse using the encoding rules for the specified binding.
      #
      # @param binding [Symbol] The binding to use `:http_redirect` or `:http_post`.
      # @param relay_state [Object] The RelayState to include in the RelayState param.
      # @return [Array] Returns an array with a url and Hash of parameters to return to the requestor.
      def response_for(binding:, relay_state: nil)
        builder = Saml::Kit::LogoutResponse.builder(self) do |x|
          yield x if block_given?
        end
        response_binding = provider.single_logout_service_for(binding: binding)
        response_binding.serialize(builder, relay_state: relay_state)
      end

      # @deprecated Use {#Saml::Kit::Builders::LogoutRequest} instead of this.
      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::LogoutRequest::Builder', 'Saml::Kit::Builders::LogoutRequest')

      private

      def single_logout_service
        return if provider.nil?
        urls = provider.single_logout_services
        urls.first
      end
    end
  end
end
