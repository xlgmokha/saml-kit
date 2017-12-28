module Xml
  module Kit
    module Templatable
      # Can be used to disable embeding a signature.
      # By default a signature will be embedded if a signing
      # certificate is available via the configuration.
      attr_accessor :embed_signature

      # @deprecated Use {#embed_signature=} instead of this method.
      def sign=(value)
        Xml::Kit.deprecate("sign= is deprecated. Use embed_signature= instead")
        self.embed_signature = value
      end

      # Returns the generated XML document with an XML Digital Signature and XML Encryption.
      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(render(self, xml: xml))
      end

      # @!visibility private
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

      # Returns true if an embedded signature is requested and at least one signing certificate is available via the configuration.
      def sign?
        return configuration.sign? if embed_signature.nil?
        embed_signature && configuration.sign?
      end

      # @!visibility private
      def signatures
        @signatures ||= ::Xml::Kit::Signatures.new(
          key_pair: configuration.key_pairs(use: :signing).last,
          digest_method: configuration.digest_method,
          signature_method: configuration.signature_method,
        )
      end

      # @!visibility private
      def encryption_for(xml:)
        if encrypt?
          temp = ::Builder::XmlMarkup.new
          yield temp
          signed_xml = signatures.complete(temp.target!)
          xml_encryption = ::Xml::Kit::Builders::XmlEncryption.new(signed_xml, encryption_certificate.public_key)
          render(xml_encryption, xml: xml)
        else
          yield xml
        end
      end

      # @!visibility private
      def encrypt?
        encrypt && encryption_certificate
      end

      # @!visibility private
      def render(model, options)
        ::Xml::Kit::Template.new(model).to_xml(options)
      end
    end
  end
end
