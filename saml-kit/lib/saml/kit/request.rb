module Saml
  module Kit
    class Request
      def self.deserialize(raw_request)
        request = Saml::Kit::Content.decode_raw_saml(raw_request)
        AuthenticationRequest.new(request)
      rescue
        InvalidRequest.new(raw_request)
      end
    end
  end
end
