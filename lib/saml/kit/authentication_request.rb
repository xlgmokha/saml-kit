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

      def response_for(user)
        Saml::Kit::Builders::Response.new(user, self)
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::AuthenticationRequest::Builder', 'Saml::Kit::Builders::AuthenticationRequest')
    end
  end
end
