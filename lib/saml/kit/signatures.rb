module Saml
  module Kit
    class Signatures
      attr_reader :sign, :configuration

      def initialize(configuration:, sign: true)
        @configuration = configuration
        @reference_ids = []
        @sign = sign
      end

      def build(reference_id)
        @reference_ids << reference_id
        XmlSignature.new(reference_id, configuration: configuration, sign: sign)
      end

      def complete(raw_xml)
        return raw_xml unless sign

        @reference_ids.each do |reference_id|
          raw_xml = Xmldsig::SignedDocument.new(raw_xml).sign(configuration.signing_private_key)
        end
        raw_xml
      end
    end
  end
end
