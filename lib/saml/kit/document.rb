
module Saml
  module Kit
    class Document
      def self.to_saml_document(saml)
        xml = Saml::Kit::Content.deserialize(saml)
        hash = Hash.from_xml(xml)
        if hash['Response'].present?
          Response.new(xml)
        elsif hash['LogoutResponse'].present?
          LogoutResponse.new(xml)
        elsif hash['AuthnRequest'].present?
          AuthenticationRequest.new(xml)
        elsif hash['LogoutRequest'].present?
          LogoutRequest.new(xml)
        end
      rescue => error
        Saml::Kit.logger.error(error)
        InvalidDocument.new(saml)
      end
    end
  end
end
