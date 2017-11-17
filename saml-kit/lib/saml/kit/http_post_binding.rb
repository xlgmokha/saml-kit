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
        if params['SAMLRequest'].present?
          deserialize_request(params['SAMLRequest'])
        elsif params['SAMLResponse'].present?
          deserialize_response(params['SAMLResponse'])
        else
          raise ArgumentError.new("Missing SAMLRequest or SAMLResponse")
        end
      end
    end
  end
end
