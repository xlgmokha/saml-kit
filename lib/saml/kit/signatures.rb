module Saml
  module Kit
    class Signatures
      attr_reader :sign, :configuration

      def initialize(configuration:, sign: true)
        @configuration = configuration
        @sign = sign
      end

      def build(reference_id)
        return nil unless sign
        Saml::Kit::Builders::XmlSignature.new(reference_id, configuration: configuration, sign: sign)
      end

      def complete(raw_xml)
        return raw_xml unless sign
        private_key = configuration.signing_private_key
        Xmldsig::SignedDocument.new(raw_xml).sign(private_key)
      end
    end
  end
end
