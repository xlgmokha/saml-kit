module Saml
  module Kit
    module Templatable
      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(Template.new(self).to_xml(xml: xml))
      end

      def signature_for(reference_id:, xml:)
        return unless sign
        Template.new(signatures.build(reference_id)).to_xml(xml: xml)
      end

      def signatures
        @signatures ||= Saml::Kit::Signatures.new(configuration: configuration, sign: sign)
      end

      def encryption_for(xml:)
        if encrypt && encryption_certificate
          temp = ::Builder::XmlMarkup.new
          yield temp
          xml_encryption = Saml::Kit::Builders::XmlEncryption.new(temp.target!, encryption_certificate.public_key)
          Template.new(xml_encryption).to_xml(xml: xml)
        else
          yield xml
        end
      end
    end
  end
end
