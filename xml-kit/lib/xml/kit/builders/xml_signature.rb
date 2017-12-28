module Xml
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

        attr_reader :certificate
        attr_reader :digest_method
        attr_reader :reference_id
        attr_reader :signature_method

        def initialize(reference_id, signature_method: :SH256, digest_method: :SHA256, certificate:)
          @certificate = certificate
          @digest_method = DIGEST_METHODS[digest_method]
          @reference_id = reference_id
          @signature_method = SIGNATURE_METHODS[signature_method]
        end
      end
    end
  end
end
