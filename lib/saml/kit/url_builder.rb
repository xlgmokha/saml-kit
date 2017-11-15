module Saml
  module Kit
    class UrlBuilder
      def initialize(private_key: Saml::Kit.configuration.signing_private_key)
        @private_key = private_key
      end

      def build(saml_document, binding:, relay_state: nil)
        payload = {
          saml_document.query_string_parameter => Content.encode_raw_saml(saml_document.to_xml),
          'RelayState' => relay_state,
          'SigAlg' => Saml::Kit::Namespaces::SHA256,
        }.map do |(x, y)|
          "#{x}=#{y}"
        end.join('&')
        payload = URI.encode(payload)
        "#{saml_document.destination}?#{payload}&Signature=#{signature_for(payload)}"
      end

      private

      attr_reader :private_key

      def signature_for(payload)
        Base64.strict_encode64(private_key.sign(OpenSSL::Digest::SHA256.new, payload))
      end
    end
  end
end
