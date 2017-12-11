module Saml
  module Kit
    class XmlSignature
      SIGNATURE_METHODS = {
        SHA1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        SHA224: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
        SHA256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        SHA384: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        SHA512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
      }.freeze
      DIGEST_METHODS = {
        SHA1: "http://www.w3.org/2000/09/xmldsig#SHA1",
        SHA224: "http://www.w3.org/2001/04/xmldsig-more#sha224",
        SHA256: "http://www.w3.org/2001/04/xmlenc#sha256",
        SHA384: "http://www.w3.org/2001/04/xmldsig-more#sha384",
        SHA512: "http://www.w3.org/2001/04/xmlenc#sha512",
      }.freeze

      attr_reader :sign, :configuration
      attr_reader :reference_id
      attr_reader :stripped_signing_certificate

      def initialize(reference_id, configuration:, sign: true)
        @configuration = configuration
        @reference_id = reference_id
        @sign = sign
        @stripped_signing_certificate = configuration.stripped_signing_certificate
      end

      def signature_method
        SIGNATURE_METHODS[configuration.signature_method]
      end

      def digest_method
        DIGEST_METHODS[configuration.digest_method]
      end
    end

    class Signatures
      attr_reader :sign, :configuration

      def initialize(configuration:, sign: true)
        @configuration = configuration
        @reference_ids = []
        @sign = sign
      end

      def build(reference_id)
        @reference_ids << reference_id
        XmlSignature.new(reference_id, configuration: configuration, sign: sign)
      end

      def complete(raw_xml)
        return raw_xml unless sign

        @reference_ids.each do |reference_id|
          raw_xml = Xmldsig::SignedDocument.new(raw_xml).sign(configuration.signing_private_key)
        end
        raw_xml
      end
    end

    module Templatable
      def to_xml(xml: ::Builder::XmlMarkup.new)
        signatures.complete(Template.new(self).to_xml(xml: xml))
      end

      def signature_for(reference_id: , xml:)
        return unless sign
        signature = signatures.build(reference_id)
        Template.new(signature).to_xml(xml: xml)
      end

      def signatures
        @signatures ||= Saml::Kit::Signatures.new(configuration: configuration, sign: sign)
      end

      def encryption_for(xml:)
        if encrypt && encryption_certificate
          temp = ::Builder::XmlMarkup.new
          yield temp
          xml_encryption = XmlEncryption.new(temp.target!, encryption_certificate.public_key)
          Template.new(xml_encryption).to_xml(xml: xml)
        else
          yield xml
        end
      end
    end
  end
end
