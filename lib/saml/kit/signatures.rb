module Saml
  module Kit
    class Signatures
      attr_reader :configuration

      def initialize(configuration:)
        @configuration = configuration
      end

      def build(reference_id)
        return nil unless configuration.sign?
        Saml::Kit::Builders::XmlSignature.new(reference_id, configuration: configuration)
      end

      def complete(raw_xml)
        return raw_xml unless configuration.sign?
        private_key = configuration.private_keys(use: :signing).sample
        Xmldsig::SignedDocument.new(raw_xml).sign(private_key)
      end
    end
  end
end
