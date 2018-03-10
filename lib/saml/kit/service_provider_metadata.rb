# frozen_string_literal: true

module Saml
  module Kit
    # This class represents a
    # SPSSODescriptor element in a
    # SAML metadata document.
    # {include:file:spec/examples/service_provider_metadata_spec.rb}
    class ServiceProviderMetadata < Metadata
      def initialize(xml)
        super('SPSSODescriptor', xml)
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
        attribute = at_xpath("/md:EntityDescriptor/md:#{name}").attribute('WantAssertionsSigned')
        return true if attribute.nil?
        attribute.text.casecmp('true').zero?
      end

      # @!visibility private
      def self.builder_class
        Saml::Kit::Builders::ServiceProviderMetadata
      end
    end
  end
end
