module Saml
  module Kit
    module Bindings
      class UrlBuilder
        include Serializable
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration)
          @configuration = configuration
        end

        def build(saml_document, relay_state: nil)
          payload = canonicalize(saml_document, relay_state)
          if configuration.sign?
            "#{saml_document.destination}?#{payload}&Signature=#{signature_for(payload)}"
          else
            "#{saml_document.destination}?#{payload}"
          end
        end

        private

        def signature_for(payload)
          private_key = configuration.signing_private_key
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
end
