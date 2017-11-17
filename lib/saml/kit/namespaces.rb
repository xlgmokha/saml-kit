module Saml
  module Kit
    module Namespaces
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      ATTR_SPLAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:*"
      BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
      BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
      EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      ENVELOPED_SIG = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
      HTTP_ARTIFACT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'
      HTTP_POST = POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
      PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
      PASSWORD_PROTECTED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
      PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
      REQUESTER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Requester"
      RESPONDER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder"
      RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
      RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
      RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
      RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
      SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
      SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256'
      SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
      SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512'
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
      TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"
      URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      VERSION_MISMATCH_ERROR = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
      XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"

      def self.binding_for(binding)
        if :post == binding
          Namespaces::HTTP_POST
        elsif :http_redirect == binding
          Namespaces::HTTP_REDIRECT
        else
          nil
        end
      end
    end
  end
end
