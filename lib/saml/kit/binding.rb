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
        []
      end

      def deserialize(params)
        raise ArgumentError.new("Unsupported binding")
      end

      def to_h
        { binding: binding, location: location }
      end

      protected

      def deserialize_request(raw_request)
        xml = Saml::Kit::Content.deserialize(raw_request)
        hash = Hash.from_xml(xml)
        if hash['AuthnRequest'].present?
          AuthenticationRequest.new(xml)
        else
          LogoutRequest.new(xml)
        end
      rescue => error
        Saml::Kit.logger.error(error)
        Saml::Kit.logger.error(error.backtrace.join("\n"))
        InvalidRequest.new(raw_request)
      end

      def deserialize_response(saml_response)
        xml = Saml::Kit::Content.deserialize(saml_response)
        hash = Hash.from_xml(xml)
        if hash['Response'].present?
          Response.new(xml)
        else
          LogoutResponse.new(xml)
        end
      rescue => error
        Saml::Kit.logger.error(error)
        Saml::Kit.logger.error(error.backtrace.join("\n"))
        InvalidResponse.new(saml_response)
      end
    end
  end
end
