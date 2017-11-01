module Saml
  module Kit
    class Signature
      XMLDSIG="http://www.w3.org/2000/09/xmldsig#"
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
        xml.tag! "ds:Signature", "xmlns:ds" => XMLDSIG do
          xml.tag! "ds:SignedInfo", "xmlns:ds" => XMLDSIG do
            xml.tag! "ds:CanonicalizationMethod", Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"
            xml.tag! "ds:SignatureMethod", Algorithm: SIGNATURE_METHODS[configuration.signature_method]
            xml.tag! "ds:Reference", URI: "##{reference_id}" do
              xml.tag! "ds:Transforms" do
                xml.tag! "ds:Transform", Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
                xml.tag! "ds:Transform", Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"
              end
              xml.tag! "ds:DigestMethod", Algorithm: DIGEST_METHODS[configuration.digest_method]
              xml.tag! "ds:DigestValue", ""
            end
          end
          xml.tag! "ds:SignatureValue", ""
          xml.tag! "ds:KeyInfo" do
            xml.tag! "ds:X509Data" do
              xml.tag! "ds:X509Certificate", configuration.stripped_certificate
            end
          end
        end
      end

      def finalize(xml)
        document = Xmldsig::SignedDocument.new(xml.target!)
        document.sign(configuration.private_key)
      end
    end
  end
end
