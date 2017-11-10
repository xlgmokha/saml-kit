module Saml
  module Kit
    class Request
      def self.encode(document)
        Saml::Kit::Content.encode_raw_saml(document.to_xml)
      end

      def self.authentication(assertion_consumer_service:, entity_id: nil)
        builder = AuthenticationRequest::Builder.new
        builder.acs_url = assertion_consumer_service
        builder.entity_id = entity_id unless entity_id.blank?
        encode(builder)
      end

      def self.decode(raw_request)
        request = Saml::Kit::Content.decode_raw_saml(raw_request)
        AuthenticationRequest.new(request)
      end
    end
  end
end
