module Saml
  module Kit
    class HttpPostBinding < Binding
      include Serializable

      def initialize(location:)
        super(binding: Saml::Kit::Namespaces::HTTP_POST, location: location)
      end

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
        xml = decode(saml_param_from(params))
        Saml::Kit::Document.to_saml_document(xml)
      end
    end
  end
end
