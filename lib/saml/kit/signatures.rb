module Saml
  module Kit
    # @!visibility private
    class Signatures # :nodoc:
      # @!visibility private
      attr_reader :configuration

      # @!visibility private
      def initialize(configuration:)
        @configuration = configuration
        @key_pair = configuration.key_pairs(use: :signing).last
      end

      # @!visibility private
      def sign_with(key_pair)
        @key_pair = key_pair
      end

      # @!visibility private
      def build(reference_id)
        return nil unless configuration.sign?
        certificate = @key_pair.certificate
        Saml::Kit::Builders::XmlSignature.new(reference_id, configuration: configuration, certificate: certificate)
      end

      # @!visibility private
      def complete(raw_xml)
        return raw_xml unless configuration.sign?
        private_key = @key_pair.private_key
        Xmldsig::SignedDocument.new(raw_xml).sign(private_key)
      end

      # @!visibility private
      def self.sign(xml: ::Builder::XmlMarkup.new, configuration: Saml::Kit.configuration)
        signatures = Saml::Kit::Signatures.new(configuration: configuration)
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
