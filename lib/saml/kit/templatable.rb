module Saml
  module Kit
    module Templatable
      attr_accessor :sign

      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(render(self, xml: xml))
      end

      def signature_for(reference_id:, xml:)
        return unless sign?
        render(signatures.build(reference_id), xml: xml)
      end

      def sign?
        sign.nil? ? configuration.sign? : sign && configuration.sign?
      end

      def signatures
        @signatures ||= Saml::Kit::Signatures.new(configuration: configuration)
      end

      def encryption_for(xml:)
        if encrypt?
          temp = ::Builder::XmlMarkup.new
          yield temp
          xml_encryption = Saml::Kit::Builders::XmlEncryption.new(temp.target!, encryption_certificate.public_key)
          render(xml_encryption, xml: xml)
        else
          yield xml
        end
      end

      def encrypt?
        encrypt && encryption_certificate
      end

      def render(model, options)
        Saml::Kit::Template.new(model).to_xml(options)
      end
    end
  end
end
