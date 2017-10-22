module Saml
  module Kit
    class SamlRequest
      def self.decode(raw_request)
        AuthenticationRequest.new(Base64.decode64(raw_request))
      end
    end
  end
end
