module Saml
  module Kit
    class UrlBuilder
      include Serializable

      def initialize(private_key: Saml::Kit.configuration.signing_private_key)
        @private_key = private_key
      end

      def build(saml_document, relay_state: nil)
        payload = canonicalize(saml_document, relay_state)
        "#{saml_document.destination}?#{payload}&Signature=#{signature_for(payload)}"
      end

      private

      attr_reader :private_key

      def signature_for(payload)
        encode(private_key.sign(OpenSSL::Digest::SHA256.new, payload))
      end

      def canonicalize(saml_document, relay_state)
        {
          saml_document.query_string_parameter => serialize(saml_document.to_xml),
          'RelayState' => relay_state,
          'SigAlg' => Saml::Kit::Namespaces::SHA256,
        }.map do |(key, value)|
          value.present? ? "#{key}=#{escape(value)}" : nil
        end.compact.join('&')
      end

      def serialize(value)
        encode(deflate(value))
      end
    end
  end
end
