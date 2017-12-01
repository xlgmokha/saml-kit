module Saml
  module Kit
    class IdentityProviderMetadata < Metadata
      def initialize(xml)
        super("IDPSSODescriptor", xml)
      end

      def want_authn_requests_signed
        xpath = "/md:EntityDescriptor/md:#{name}"
        attribute = document.find_by(xpath).attribute("WantAuthnRequestsSigned")
        return true if attribute.nil?
        attribute.text.downcase == "true"
      end

      def single_sign_on_services
        services('SingleSignOnService')
      end

      def single_sign_on_service_for(binding:)
        service_for(binding: binding, type: 'SingleSignOnService')
      end

      def attributes
        document.find_all("/md:EntityDescriptor/md:#{name}/saml:Attribute").map do |item|
          {
            format: item.attribute("NameFormat").try(:value),
            name: item.attribute("Name").value,
          }
        end
      end

      def login_request_for(binding:, relay_state: nil)
        builder = Saml::Kit::AuthenticationRequest.builder do |x|
          yield x if block_given?
        end
        request_binding = single_sign_on_service_for(binding: binding)
        request_binding.serialize(builder, relay_state: relay_state)
      end

      def logout_request_for(user, binding: :http_post, relay_state: nil)
        builder = Saml::Kit::LogoutRequest.builder(user) do |x|
          yield x if block_given?
        end
        request_binding = single_logout_service_for(binding: binding)
        request_binding.serialize(builder, relay_state: relay_state)
      end

      def self.builder_class
        Saml::Kit::Builders::IdentityProviderMetadata
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::IdentityProviderMetadata::Builder', 'Saml::Kit::Builders::IdentityProviderMetadata')
    end
  end
end
