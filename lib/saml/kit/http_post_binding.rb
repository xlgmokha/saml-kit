module Saml
  module Kit
    class HttpPostBinding < Binding
      def serialize(builder, relay_state: nil)
        builder.sign = true
        builder.destination = location
        document = builder.build
        saml_params = {
          document.query_string_parameter => Base64.strict_encode64(document.to_xml),
        }
        saml_params['RelayState'] = relay_state if relay_state.present?
        [location, saml_params]
      end

      def deserialize(params)
        saml_param = saml_param_from(params)
        Saml::Kit::Document.to_saml_document(saml_param)
      end
    end
  end
end
