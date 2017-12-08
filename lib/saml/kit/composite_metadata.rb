module Saml
  module Kit
    class CompositeMetadata < Metadata
      attr_reader :service_provider, :identity_provider

      def initialize(xml)
        super("", xml)
        @service_provider = Saml::Kit::ServiceProviderMetadata.new(xml)
        @identity_provider = Saml::Kit::IdentityProviderMetadata.new(xml)
      end

      def single_sign_on_services
        identity_provider.single_sign_on_services
      end

      def single_sign_on_service_for(*args)
        identity_provider.single_sign_on_service_for(*args)
      end

      def assertion_consumer_services
        service_provider.assertion_consumer_services
      end

      def services(type)
        xpath = "//md:EntityDescriptor/md:SPSSODescriptor/md:#{type}|//md:EntityDescriptor/md:IDPSSODescriptor/md:#{type}"
        document.find_all(xpath).map do |item|
          binding = item.attribute("Binding").value
          location = item.attribute("Location").value
          Saml::Kit::Bindings.create_for(binding, location)
        end
      end
    end
  end
end
