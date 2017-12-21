module Saml
  module Kit
    module Templatable
      attr_accessor :embed_signature

      def sign=(value)
        Saml::Kit.deprecate("sign= is deprecated. Use embed_signature= instead")
        self.embed_signature = value
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(render(self, xml: xml))
      end

      def signature_for(reference_id:, xml:)
        return unless sign?
        render(signatures.build(reference_id), xml: xml)
      end

      def sign_with(key_pair)
        signatures.sign_with(key_pair)
      end

      def sign?
        embed_signature.nil? ? configuration.sign? : embed_signature && configuration.sign?
      end

      def signatures
        @signatures ||= Saml::Kit::Signatures.new(configuration: configuration)
      end

      def encryption_for(xml:)
        if encrypt?
          temp = ::Builder::XmlMarkup.new
          yield temp
          signed_xml = signatures.complete(temp.target!)
          xml_encryption = Saml::Kit::Builders::XmlEncryption.new(signed_xml, encryption_certificate.public_key)
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
