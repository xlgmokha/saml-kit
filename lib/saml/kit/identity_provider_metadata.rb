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

      def self.builder_class
        Saml::Kit::Builders::IdentityProviderMetadata
      end

      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::IdentityProviderMetadata::Builder', 'Saml::Kit::Builders::IdentityProviderMetadata')
    end
  end
end
