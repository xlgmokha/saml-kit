module Saml
  module Kit
    class SamlRequest
      def self.encode(document)
        Base64.encode64(compress(document.to_xml))
      end

      def self.compress(content)
        content
        #Zlib::Deflate.deflate(xml, 9)[2..-5]
      end

      def self.decode(raw_request)
        AuthenticationRequest.new(Base64.decode64(raw_request))
      end
    end
  end
end
