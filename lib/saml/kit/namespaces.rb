module Saml
  module Kit
    module Namespaces
      SAML_2_0 = "urn:oasis:names:tc:SAML:2.0"
      SAML_1_1 = "urn:oasis:names:tc:SAML:1.1"
      ATTR_NAME_FORMAT = "#{SAML_2_0}:attrname-format"
      NAME_ID_FORMAT_1_1 = "#{SAML_1_1}:nameid-format"
      NAME_ID_FORMAT_2_0 = "#{SAML_2_0}:nameid-format"
      STATUS = "#{SAML_2_0}:status"

      ASSERTION = "#{SAML_2_0}:assertion"
      ATTR_SPLAT = "#{ATTR_NAME_FORMAT}:*"
      BASIC = "#{ATTR_NAME_FORMAT}:basic"
      BEARER = "#{SAML_2_0}:cm:bearer"
      EMAIL_ADDRESS = "#{NAME_ID_FORMAT_1_1}:emailAddress"
      INVALID_NAME_ID_POLICY = "#{STATUS}:InvalidNameIDPolicy"
      METADATA = "#{SAML_2_0}:metadata"
      PASSWORD = "#{SAML_2_0}:ac:classes:Password"
      PASSWORD_PROTECTED = "#{SAML_2_0}:ac:classes:PasswordProtectedTransport"
      PERSISTENT = "#{NAME_ID_FORMAT_2_0}:persistent"
      PROTOCOL = "#{SAML_2_0}:protocol"
      REQUESTER_ERROR = "#{STATUS}:Requester"
      RESPONDER_ERROR = "#{STATUS}:Responder"
      SUCCESS = "#{STATUS}:Success"
      TRANSIENT = "#{NAME_ID_FORMAT_2_0}:transient"
      UNSPECIFIED = "#{SAML_2_0}:consent:unspecified"
      UNSPECIFIED_NAMEID = "#{NAME_ID_FORMAT_1_1}:unspecified"
      URI = "#{ATTR_NAME_FORMAT}:uri"
      VERSION_MISMATCH_ERROR = "#{STATUS}:VersionMismatch"
    end
  end
end
