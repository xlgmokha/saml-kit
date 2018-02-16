module Saml
  module Kit
    module Namespaces
      SAML_2_0 = 'urn:oasis:names:tc:SAML:2.0'.freeze
      SAML_1_1 = 'urn:oasis:names:tc:SAML:1.1'.freeze
      ATTR_NAME_FORMAT = "#{SAML_2_0}:attrname-format".freeze
      NAME_ID_FORMAT_1_1 = "#{SAML_1_1}:nameid-format".freeze
      NAME_ID_FORMAT_2_0 = "#{SAML_2_0}:nameid-format".freeze
      STATUS = "#{SAML_2_0}:status".freeze

      ASSERTION = "#{SAML_2_0}:assertion".freeze
      ATTR_SPLAT = "#{ATTR_NAME_FORMAT}:*".freeze
      BASIC = "#{ATTR_NAME_FORMAT}:basic".freeze
      BEARER = "#{SAML_2_0}:cm:bearer".freeze
      EMAIL_ADDRESS = "#{NAME_ID_FORMAT_1_1}:emailAddress".freeze
      INVALID_NAME_ID_POLICY = "#{STATUS}:InvalidNameIDPolicy".freeze
      METADATA = "#{SAML_2_0}:metadata".freeze
      PASSWORD = "#{SAML_2_0}:ac:classes:Password".freeze
      PASSWORD_PROTECTED = "#{SAML_2_0}:ac:classes:PasswordProtectedTransport".freeze
      PERSISTENT = "#{NAME_ID_FORMAT_2_0}:persistent".freeze
      PROTOCOL = "#{SAML_2_0}:protocol".freeze
      REQUESTER_ERROR = "#{STATUS}:Requester".freeze
      RESPONDER_ERROR = "#{STATUS}:Responder".freeze
      SUCCESS = "#{STATUS}:Success".freeze
      TRANSIENT = "#{NAME_ID_FORMAT_2_0}:transient".freeze
      UNSPECIFIED = "#{SAML_2_0}:consent:unspecified".freeze
      UNSPECIFIED_NAMEID = "#{NAME_ID_FORMAT_1_1}:unspecified".freeze
      URI = "#{ATTR_NAME_FORMAT}:uri".freeze
      VERSION_MISMATCH_ERROR = "#{STATUS}:VersionMismatch".freeze
    end
  end
end
