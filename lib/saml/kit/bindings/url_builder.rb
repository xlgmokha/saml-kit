module Saml
  module Kit
    module Bindings
      # {include:file:spec/saml/bindings/url_builder_spec.rb}
      class UrlBuilder
        include Serializable
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration)
          @configuration = configuration
        end

        def build(saml_document, relay_state: nil)
          if configuration.sign?
            payload = canonicalize(saml_document, relay_state)
            "#{saml_document.destination}?#{payload}&Signature=#{signature_for(payload)}"
          else
            payload = to_query_string(
              saml_document.query_string_parameter => serialize(saml_document.to_xml),
              'RelayState' => relay_state,
            )
            "#{saml_document.destination}?#{payload}"
          end
        end

        private

        def signature_for(payload)
          private_key = configuration.private_keys(use: :signing).last
          encode(private_key.sign(OpenSSL::Digest::SHA256.new, payload))
        end

        def canonicalize(saml_document, relay_state)
          to_query_string(
            saml_document.query_string_parameter => serialize(saml_document.to_xml),
            'RelayState' => relay_state,
            'SigAlg' => Saml::Kit::Namespaces::SHA256,
          )
        end

        def to_query_string(query_params)
          query_params.map do |(key, value)|
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
