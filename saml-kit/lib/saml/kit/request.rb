module Saml
  module Kit
    class Request
      def self.deserialize(raw_request)
        xml = Saml::Kit::Content.deserialize(raw_request)
        hash = Hash.from_xml(xml)
        if hash['AuthnRequest'].present?
          AuthenticationRequest.new(xml)
        else
          LogoutRequest.new(xml)
        end
      rescue => error
        Saml::Kit.logger.error(error)
        Saml::Kit.logger.error(error.backtrace.join("\n"))
        InvalidRequest.new(raw_request)
      end
    end
  end
end
