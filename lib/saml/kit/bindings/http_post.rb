# frozen_string_literal: true

module Saml
  module Kit
    module Bindings
      # {include:file:spec/saml/kit/bindings/http_post_spec.rb}
      class HttpPost < Binding
        include Serializable

        def initialize(location:)
          super(binding: Saml::Kit::Bindings::HTTP_POST, location: location)
        end

        def serialize(builder, relay_state: nil)
          builder.destination = location
          document = builder.build
          saml_params = {
            document.query_string_parameter => Base64.strict_encode64(document.to_xml),
          }
          saml_params['RelayState'] = relay_state if relay_state.present?
          [location, saml_params]
        end

        def deserialize(params, configuration: Saml::Kit.configuration)
          xml = decode(saml_param_from(params))
          Saml::Kit::Document.to_saml_document(xml, configuration: configuration)
        end
      end
    end
  end
end
