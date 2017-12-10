module Saml
  module Kit
    class CompositeMetadata < Metadata
      attr_reader :service_provider, :identity_provider

      def initialize(xml)
        super("IDPSSODescriptor", xml)
        @service_provider = Saml::Kit::ServiceProviderMetadata.new(xml)
        @identity_provider = Saml::Kit::IdentityProviderMetadata.new(xml)
      end

      def services(type)
        xpath = "//md:EntityDescriptor/md:SPSSODescriptor/md:#{type}|//md:EntityDescriptor/md:IDPSSODescriptor/md:#{type}"
        document.find_all(xpath).map do |item|
          binding = item.attribute("Binding").value
          location = item.attribute("Location").value
          Saml::Kit::Bindings.create_for(binding, location)
        end
      end

      def certificates
        identity_provider.certificates + service_provider.certificates
      end

      def method_missing(name, *args)
        if identity_provider.respond_to?(name)
          identity_provider.public_send(name, *args)
        elsif service_provider.respond_to?(name)
          service_provider.public_send(name, *args)
        else
          super
        end
      end
    end
  end
end
