module Saml
  module Kit
    class CompositeMetadata < Metadata
      attr_reader :service_provider, :identity_provider

      def initialize(xml)
        super("", xml)
        @service_provider = Saml::Kit::ServiceProviderMetadata.new(xml)
        @identity_provider = Saml::Kit::IdentityProviderMetadata.new(xml)
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

      def method_missing(name, *args)
        puts [name, args].inspect
        if identity_provider.respond_to?(name)
          identity_provider.public_send(name, *args)
        else
          super
        end
      end
    end
  end
end
