module Saml
  module Kit
    class Signature
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

      attr_reader :sign, :xml
      attr_reader :stripped_signing_certificate
      attr_reader :private_key
      attr_reader :configuration

      def initialize(xml, configuration:, sign: true)
        @configuration = configuration
        @private_key = configuration.signing_private_key
        @reference_ids = []
        @sign = sign
        @stripped_signing_certificate = configuration.stripped_signing_certificate
        @xml = xml
      end

      def signature_method
        SIGNATURE_METHODS[configuration.signature_method]
      end

      def digest_method
        DIGEST_METHODS[configuration.digest_method]
      end

      def template(reference_id)
        return unless sign
        return if reference_id.blank?
        @reference_ids << reference_id
        Template.new(self).to_xml(xml: xml)
      end

      def reference_id
        @reference_ids.last
      end

      def finalize
        sign ? apply_to(xml.target!) : xml.target!
      end

      def apply_to(raw_xml)
        return raw_xml unless sign

        @reference_ids.each do |reference_id|
          raw_xml = Xmldsig::SignedDocument.new(raw_xml).sign(private_key)
        end
        raw_xml
      end

      def self.sign(sign: true, xml: ::Builder::XmlMarkup.new, configuration: Saml::Kit.configuration)
        signature = new(xml, sign: sign, configuration: configuration)
        yield xml, signature
        signature.finalize
      end
    end
  end
end
