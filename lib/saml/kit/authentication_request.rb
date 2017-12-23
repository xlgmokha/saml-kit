module Saml
  module Kit
    # This class can be used to parse a SAML AuthnRequest or generate one.
    #
    # To generate an AuthnRequest use the builder API.
    #
    #    request = AuthenticationRequest.build do |builder|
    #      builder.name_id_format = [Saml::Kit::Namespaces::EMAIL_ADDRESS]
    #    end
    #
    #    <?xml version="1.0" encoding="UTF-8"?>
    #    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_ca3a0e72-9530-41f1-9518-c53716de88b2" Version="2.0" IssueInstant="2017-12-19T16:27:44Z" Destination="http://hartmann.info" AssertionConsumerServiceURL="https://carroll.com/acs">
    #      <saml:Issuer>Day of the Dangerous Cousins</saml:Issuer>
    #      <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
    #    </samlp:AuthnRequest>
    #
    # Example:
    #
    # {include:file:spec/examples/authentication_request_spec.rb}
    class AuthenticationRequest < Document
      include Requestable

      # Create an instance of an AuthnRequest document.
      #
      # @param xml [String] the raw xml.
      # @param configuration [Saml::Kit::Configuration] defaults to the global configuration.
      def initialize(xml, configuration: Saml::Kit.configuration)
        super(xml, name: "AuthnRequest", configuration: configuration)
      end

      # Extract the AssertionConsumerServiceURL from the AuthnRequest
      #    <samlp:AuthnRequest AssertionConsumerServiceURL="https://carroll.com/acs"></samlp:AuthnRequest>
      def assertion_consumer_service_url
        to_h[name]['AssertionConsumerServiceURL']
      end

      # Extract the NameIDPolicy from the AuthnRequest
      #    <samlp:AuthnRequest>
      #      <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
      #    </samlp:AuthnRequest>
      def name_id_format
        to_h[name]['NameIDPolicy']['Format']
      end

      # Generate a Response for a specific user.
      # @param user [Object] this is a custom user object that can be used for generating a nameid and assertion attributes.
      # @param binding [Symbol] the SAML binding to use `:http_post` or `:http_redirect`.
      # @param configuration [Saml::Kit::Configuration] the configuration to use to build the response.
      def response_for(user, binding:, relay_state: nil, configuration: Saml::Kit.configuration)
        response_binding = provider.assertion_consumer_service_for(binding: binding)
        builder = Saml::Kit::Response.builder(user, self, configuration: configuration) do |x|
          x.embed_signature = provider.want_assertions_signed
          yield x if block_given?
        end
        response_binding.serialize(builder, relay_state: relay_state)
      end

      # @deprecated Use {#Saml::Kit::Builders::AuthenticationRequest} instead of this.
      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::AuthenticationRequest::Builder', 'Saml::Kit::Builders::AuthenticationRequest')
    end
  end
end
