module Saml
  module Kit
    class Signature
      attr_reader :signatures
      attr_reader :xml

      def initialize(xml, signatures)
        @signatures = signatures
        @xml = xml
      end

      def template(reference_id)
        Template.new(signatures.build(reference_id)).to_xml(xml: xml)
      end

      def self.sign(xml: ::Builder::XmlMarkup.new, configuration: Saml::Kit.configuration)
        signatures = Saml::Kit::Signatures.new(configuration: configuration)
        yield xml, new(xml, signatures)
        signatures.complete(xml.target!)
      end
    end
  end
end
