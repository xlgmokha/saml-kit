module Saml
  module Kit
    class AuthenticationRequest < Document
      include Requestable

      def initialize(xml)
        super(xml, name: "AuthnRequest")
      end

      def acs_url
        to_h[name]['AssertionConsumerServiceURL']
      end

      def name_id_format
        to_h[name]['NameIDPolicy']['Format']
      end

      def response_for(user, binding:, relay_state: nil)
        response_binding = provider.assertion_consumer_service_for(binding: binding)
        builder = Saml::Kit::Response.builder(user, self) do |x|
          x.sign = provider.want_assertions_signed
          yield x if block_given?
        end
        response_binding.serialize(builder, relay_state: relay_state)
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::AuthenticationRequest::Builder', 'Saml::Kit::Builders::AuthenticationRequest')
    end
  end
end
