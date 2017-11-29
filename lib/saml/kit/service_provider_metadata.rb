module Saml
  module Kit
    class ServiceProviderMetadata < Metadata
      def initialize(xml)
        super("SPSSODescriptor", xml)
      end

      def assertion_consumer_services
        services('AssertionConsumerService')
      end

      def assertion_consumer_service_for(binding:)
        service_for(binding: binding, type: 'AssertionConsumerService')
      end

      def want_assertions_signed
        attribute = document.find_by("/md:EntityDescriptor/md:#{name}").attribute("WantAssertionsSigned")
        attribute.text.downcase == "true"
      end
    end
  end
end
