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

    class HttpRedirectBinding < Binding
      def serialize(builder, relay_state: nil)
        builder.sign = false
        builder.destination = location
        document = builder.build
        [UrlBuilder.new.build(document, relay_state: relay_state), {}]
      end

      def deserialize(params)
        document = deserialize_document_from!(params)
        ensure_valid_signature!(params, document)
        document
      end

      private

      def deserialize_document_from!(params)
        if params['SAMLRequest'].present?
          deserialize_request(CGI.unescape(params['SAMLRequest']))
        elsif params['SAMLResponse'].present?
          deserialize_response(CGI.unescape(params['SAMLResponse']))
        else
          raise ArgumentError.new("SAMLRequest or SAMLResponse parameter is required.")
        end
      end

      def ensure_valid_signature!(params, document)
        return if params['Signature'].blank? || params['SigAlg'].blank?

        signature = Base64.decode64(params['Signature'])
        canonical_form = ['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg'].map do |key|
          value = params[key]
          value.present? ? "#{key}=#{value}" : nil
        end.compact.join('&')

        valid = document.provider.verify(algorithm_for(params['SigAlg']), signature, canonical_form)
        raise ArgumentError.new("Invalid Signature") unless valid
      end


      def algorithm_for(algorithm)
        case algorithm =~ /(rsa-)?sha(.*?)$/i && $2.to_i
        when 256
          OpenSSL::Digest::SHA256.new
        when 384
          OpenSSL::Digest::SHA384.new
        when 512
          OpenSSL::Digest::SHA512.new
        else
          OpenSSL::Digest::SHA1.new
        end
      end

    end
  end
end
