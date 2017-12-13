module Saml
  module Kit
    module Builders
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
        attr_reader :x509_certificate

        def initialize(reference_id, configuration:, sign: true)
          @configuration = configuration
          @reference_id = reference_id
          @sign = sign
          @x509_certificate = configuration.certificates(use: :signing).last.stripped
        end

        def signature_method
          SIGNATURE_METHODS[configuration.signature_method]
        end

        def digest_method
          DIGEST_METHODS[configuration.digest_method]
        end
      end
    end
  end
end
