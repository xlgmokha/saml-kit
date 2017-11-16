module Saml
  module Kit
    class UrlBuilder
      def initialize(private_key: Saml::Kit.configuration.signing_private_key)
        @private_key = private_key
      end

      def build(saml_document, relay_state: nil)
        payload = build_payload(saml_document, relay_state)
        "#{saml_document.destination}?#{payload}&Signature=#{signature_for(payload)}"
      end

      private

      attr_reader :private_key

      def signature_for(payload)
        Base64.strict_encode64(private_key.sign(OpenSSL::Digest::SHA256.new, payload))
      end

      def build_payload(saml_document, relay_state)
        {
          saml_document.query_string_parameter => Content.serialize(saml_document.to_xml, compress: true),
          'RelayState' => relay_state,
          'SigAlg' => Saml::Kit::Namespaces::SHA256,
        }.map do |(key, value)|
          value.present? ? "#{key}=#{CGI.escape(value)}" : nil
        end.compact.join('&')
      end
    end
  end
end
