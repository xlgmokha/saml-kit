module Saml
  module Kit
    class Signatures
      attr_reader :sign, :configuration

      def initialize(configuration:, sign: true)
        @configuration = configuration
        @sign = sign
      end

      def build(reference_id)
        XmlSignature.new(reference_id, configuration: configuration, sign: sign)
      end

      def complete(raw_xml)
        return raw_xml unless sign

        Xmldsig::SignedDocument.new(raw_xml).sign(private_key)
      end

      private

      def private_key
        configuration.signing_private_key
      end
    end
  end
end
