module Saml
  module Kit
    module Templatable
      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(render(self, xml: xml))
      end

      def signature_for(reference_id:, xml:)
        return unless sign
        render(signatures.build(reference_id), xml: xml)
      end

      def signatures
        @signatures ||= Saml::Kit::Signatures.new(configuration: configuration, sign: sign)
      end

      def encryption_for(xml:)
        if encrypt && encryption_certificate
          temp = ::Builder::XmlMarkup.new
          yield temp
          xml_encryption = Saml::Kit::Builders::XmlEncryption.new(temp.target!, encryption_certificate.public_key)
          render(xml_encryption, xml: xml)
        else
          yield xml
        end
      end

      def render(model, options)
        Saml::Kit::Template.new(model).to_xml(options)
      end
    end
  end
end
