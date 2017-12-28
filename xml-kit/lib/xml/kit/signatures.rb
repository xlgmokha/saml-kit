module Xml
  module Kit
    # @!visibility private
    class Signatures # :nodoc:
      attr_reader :key_pair, :signature_method, :digest_method

      # @!visibility private
      def initialize(key_pair:, signature_method:, digest_method:)
        @digest_method = digest_method
        @key_pair = key_pair
        @signature_method = signature_method
      end

      # @!visibility private
      def sign_with(key_pair)
        @key_pair = key_pair
      end

      # @!visibility private
      def build(reference_id)
        return nil if key_pair.nil?

        ::Xml::Kit::Builders::Signature.new(
          reference_id,
          certificate: key_pair.certificate,
          signature_method: signature_method,
          digest_method: digest_method
        )
      end

      # @!visibility private
      def complete(raw_xml)
        return raw_xml if key_pair.nil?

        private_key = key_pair.private_key
        Xmldsig::SignedDocument.new(raw_xml).sign(private_key)
      end

      # @!visibility private
      def self.sign(xml: ::Builder::XmlMarkup.new, key_pair:, signature_method: :SHA256, digest_method: :SHA256)
        signatures = new(
          key_pair: key_pair,
          signature_method: signature_method,
          digest_method: digest_method,
        )
        yield xml, XmlSignatureTemplate.new(xml, signatures)
        signatures.complete(xml.target!)
      end

      class XmlSignatureTemplate # :nodoc:
        # @!visibility private
        attr_reader :signatures, :xml

        # @!visibility private
        def initialize(xml, signatures)
          @signatures = signatures
          @xml = xml
        end

        # @!visibility private
        def template(reference_id)
          Template.new(signatures.build(reference_id)).to_xml(xml: xml)
        end
      end
    end
  end
end
