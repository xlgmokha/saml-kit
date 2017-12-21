module Saml
  module Kit
    class ServiceProviderMetadata < Metadata
      def initialize(xml)
        super("SPSSODescriptor", xml)
      end

      # Returns each of the AssertionConsumerService bindings.
      def assertion_consumer_services
        services('AssertionConsumerService')
      end

      # Returns the AssertionConsumerService for the specified binding.
      #
      # @param binding [Symbol] can be either `:http_post` or `:http_redirect`
      def assertion_consumer_service_for(binding:)
        service_for(binding: binding, type: 'AssertionConsumerService')
      end

      # Returns true when the metadata demands that Assertions must be signed.
      def want_assertions_signed
        attribute = document.find_by("/md:EntityDescriptor/md:#{name}").attribute("WantAssertionsSigned")
        return true if attribute.nil?
        attribute.text.downcase == "true"
      end

      # @!visibility private
      def self.builder_class
        Saml::Kit::Builders::ServiceProviderMetadata
      end

      # @deprecated Use 'Saml::Kit::Builders::ServiceProviderMetadata'.
      Builder = ActiveSupport::Deprecation::DeprecatedConstantProxy.new('Saml::Kit::ServiceProviderMetadata::Builder', 'Saml::Kit::Builders::ServiceProviderMetadata')
    end
  end
end
