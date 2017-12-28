module Xml
  module Kit
    module Templatable
      # Can be used to disable embeding a signature.
      # By default a signature will be embedded if a signing
      # certificate is available.
      attr_accessor :embed_signature

      # Used to enable/disable encrypting the document.
      attr_accessor :encrypt

      # The [Xml::Kit::KeyPair] to use for generating a signature.
      attr_accessor :signing_key_pair

      # The [Xml::Kit::Certificate] that contains the public key to use for encrypting the document.
      attr_accessor :encryption_certificate

      # Returns the generated XML document with an XML Digital Signature and XML Encryption.
      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(render(self, xml: xml))
      end

      def encryption_for(xml:)
        if encrypt?
          temp = ::Builder::XmlMarkup.new
          yield temp
          signed_xml = signatures.complete(temp.target!)
          xml_encryption = ::Xml::Kit::Builders::XmlEncryption.new(
            signed_xml,
            encryption_certificate.public_key
          )
          render(xml_encryption, xml: xml)
        else
          yield xml
        end
      end

      def render(model, options)
        ::Xml::Kit::Template.new(model).to_xml(options)
      end

      def signature_for(reference_id:, xml:)
        return unless sign?
        render(signatures.build(reference_id), xml: xml)
      end

      # Allows you to specify which key pair to use for generating an XML digital signature.
      #
      # @param key_pair [Xml::Kit::KeyPair] the key pair to use for signing.
      def sign_with(key_pair)
        signatures.sign_with(key_pair)
      end

      private

      def sign?
        embed_signature
      end

      # @!visibility private
      def signatures
        @signatures ||= ::Xml::Kit::Signatures.new(
          key_pair: signing_key_pair,
          digest_method: digest_method,
          signature_method: signature_method,
        )
      end

      def digest_method
        :SHA256
      end

      def signature_method
        :SHA256
      end

      # @!visibility private
      def encrypt?
        encrypt && encryption_certificate
      end
    end
  end
end
