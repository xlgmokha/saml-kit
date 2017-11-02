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

      attr_reader :configuration, :reference_id

      def initialize(reference_id, configuration = Saml::Kit.configuration)
        @reference_id = reference_id
        @configuration = configuration
      end

      def template(xml = ::Builder::XmlMarkup.new)
        xml.Signature "xmlns" => Namespaces::XMLDSIG do
          xml.SignedInfo do
            xml.CanonicalizationMethod Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"
            xml.SignatureMethod Algorithm: SIGNATURE_METHODS[configuration.signature_method]
            xml.Reference URI: "#_#{reference_id}" do
              xml.Transforms do
                xml.Transform Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
                xml.Transform Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"
              end
              xml.DigestMethod Algorithm: DIGEST_METHODS[configuration.digest_method]
              xml.DigestValue ""
            end
          end
          xml.SignatureValue ""
          xml.KeyInfo do
            xml.X509Data do
              xml.X509Certificate configuration.stripped_signing_certificate
            end
          end
        end
      end

      def finalize(xml)
        document = Xmldsig::SignedDocument.new(xml.target!)
        document.sign(configuration.signing_private_key)
      end
    end
  end
end
