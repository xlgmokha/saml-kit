module Saml
  module Kit
    class Signature
      attr_reader :sign, :xml
      attr_reader :configuration

      def initialize(xml, configuration:, sign: true)
        @configuration = configuration
        @sign = sign
        @xml = xml
      end

      def template(reference_id)
        return unless sign
        signature = signatures.build(reference_id)
        Template.new(signature).to_xml(xml: xml)
      end

      def finalize
        signatures.complete(xml.target!)
      end

      def self.sign(sign: true, xml: ::Builder::XmlMarkup.new, configuration: Saml::Kit.configuration)
        signature = new(xml, sign: sign, configuration: configuration)
        yield xml, signature
        signature.finalize
      end

      private

      def signatures
        @signatures ||= Saml::Kit::Signatures.new(configuration: configuration, sign: sign)
      end
    end
  end
end
