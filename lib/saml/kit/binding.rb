module Saml
  module Kit
    class Binding
      attr_reader :binding, :location

      def initialize(binding:, location:)
        @binding = binding
        @location = location
      end

      def binding?(other)
        binding == other
      end

      def serialize(builder, relay_state: nil)
        if http_redirect?
          builder.sign = false
          builder.destination = location
          document = builder.build
          [UrlBuilder.new.build(document, relay_state: relay_state), {}]
        elsif post?
          builder.sign = true
          builder.destination = location
          document = builder.build
          saml_params = {
            document.query_string_parameter => Base64.strict_encode64(document.to_xml),
            'RelayState' => relay_state,
          }
          [location, saml_params]
        else
          []
        end
      end

      def http_redirect?
        binding == Namespaces::HTTP_REDIRECT
      end

      def post?
        binding == Namespaces::POST
      end

      def to_h
        { binding: binding, location: location }
      end
    end
  end
end
