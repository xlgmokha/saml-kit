module Saml
  module Kit
    class UrlBuilder
      def build(request, binding:, relay_state: nil)
        payload = {
          'SAMLRequest' => Content.encode_raw_saml(request.to_xml),
          'RelayState' => relay_state,
          'SigAlg' => Saml::Kit::Namespaces::SHA256,
        }.map do |(x, y)|
          "#{x}=#{y}"
        end.join('&')
        payload = URI.encode(payload)
        "#{request.destination}?#{payload}&Signature=#{signature_for(payload)}"
      end

      private

      def private_key
        Saml::Kit.configuration.signing_private_key
      end

      def signature_for(payload)
        Base64.strict_encode64(private_key.sign(OpenSSL::Digest::SHA256.new, payload))
      end
    end
  end
end
