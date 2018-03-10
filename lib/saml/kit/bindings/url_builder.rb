# frozen_string_literal: true

module Saml
  module Kit
    module Bindings
      # This class is responsible for
      # generating a url as per the
      # rules for the HTTP redirect binding
      # specification.
      # https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
      # {include:file:spec/saml/kit/bindings/url_builder_spec.rb}
      class UrlBuilder
        include Serializable
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration)
          @configuration = configuration
        end

        def build(saml_document, relay_state: nil)
          destination = saml_document.destination
          if configuration.sign?
            payload = canonicalize(saml_document, relay_state)
            "#{destination}?#{payload}&Signature=#{signature_for(payload)}"
          else
            payload = to_query_string(
              saml_document.query_string_parameter => serialize(saml_document.to_xml),
              'RelayState' => relay_state
            )
            "#{destination}?#{payload}"
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
            'SigAlg' => ::Xml::Kit::Namespaces::SHA256
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
