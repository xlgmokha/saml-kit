module Saml
  module Kit
    module Namespaces
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      ATTR_SPLAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:*"
      BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
      BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
      EMAIL_ADDRESS = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
      HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
      PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
      PASSWORD_PROTECTED = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
      PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
      SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
      TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:consent:unspecified"
      URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
      XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"

      def self.binding_for(binding)
        if :post == binding
          Namespaces::POST
        else
          Namespaces::HTTP_REDIRECT
        end
      end
    end
  end
end
