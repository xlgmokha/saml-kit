module Saml
  module Kit
    class Request
      def self.encode(document)
        Base64.encode64(compress(document.to_xml))
      end

      def self.authentication(assertion_consumer_service:, entity_id: nil)
        builder = AuthenticationRequest::Builder.new
        builder.acs_url = assertion_consumer_service
        builder.entity_id = entity_id unless entity_id.blank?
        encode(builder)
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
